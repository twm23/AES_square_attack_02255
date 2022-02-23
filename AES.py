from asyncio import run_coroutine_threadsafe
import binascii

from Delta_set import delta_set
from reverse_last_round import rev_last_round, check_guess
from s_box import lookup

# last round key field
last_round_key = []

# breaks the data in grids of 16 bytes in order to generate AES states, where each element in the grid is a byte
def break_in_grids_of_16(s):
    all = []
    for i in range(len(s) // 16):
        b = s[i * 16: i * 16 + 16]
        grid = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                grid[i].append(b[i + j * 4])
        all.append(grid)
    return all


# function that shifts a row according to which row it is, i.e row 3 will be shifted 2 times to the left
def shift_row(row, n=1):
    return row[n:] + row[:n]


# AES key schedule to get round keys for each round from one initial key
def key_schedule(key, rounds):
    # round constant
    rcon = [[1, 0, 0, 0]]
    for _ in range(1, rounds):
        rcon.append([rcon[-1][0] * 2, 0, 0, 0])
        if rcon[-1][0] > 0x80:
            rcon[-1][0] ^= 0x11b

    # represent the key in 4 by 4 grid format, just like the AES state
    key_grid = break_in_grids_of_16(key)[0]

    # generate round keys for each round
    for round in range(rounds):
        last_column = [row[-1] for row in key_grid]
        # Shift row step
        last_column_shift_row = shift_row(last_column)
        # s-box look-up
        last_column_sbox_step = [lookup(b) for b in last_column_shift_row]
        last_column_rcon_step = [last_column_sbox_step[i]
                                 ^ rcon[round][i] for i in range(len(last_column_shift_row))]

        for r in range(4):
            key_grid[r] += bytes([last_column_rcon_step[r]
                                  ^ key_grid[r][round * 4]])

        for i in range(len(key_grid)):
            for j in range(1, 4):
                key_grid[i] += bytes([key_grid[i][round * 4 + j]
                                      ^ key_grid[i][round * 4 + j + 3]])
    # return round key
    return key_grid


def multiply_by_2(v):
    # shift the byte to the left by 1
    s = v << 1
    # reduce the size of s to 8 bits (1 byte)
    s = s & 0xff

    # check if most significant bit is 1 or 0
    if (v & 128) != 0:
        # XOR with the irreducible polynomial for x^8=x^4+x^3+x+1 in GF(2^8), to
        s = s ^ 0x1b
    return s


# function that multiplies a byte with 3 in the mixedcolumn, which is the same as multiplying the byte with 2 and then XOR with the byte, as 3 = 2 XOR 1
def multiply_by_3(v):
    return multiply_by_2(v) ^ v


# function that does the mix-column operations for each column in a AES state
def mix_column(column):
    # in galois fields addition means XOR, so each multiplication is XOR with eachother
    # the mix column matrix is:  [[ 2, 3, 1, 1],
    #                            [ 1, 2, 3, 1],
    #                            [ 1, 1, 2, 3],
    #                            [ 3, 1, 1, 2]]
    r = [
        multiply_by_2(column[0]) ^ multiply_by_3(
            column[1]) ^ column[2] ^ column[3],
        multiply_by_2(column[1]) ^ multiply_by_3(
            column[2]) ^ column[3] ^ column[0],
        multiply_by_2(column[2]) ^ multiply_by_3(
            column[3]) ^ column[0] ^ column[1],
        multiply_by_2(column[3]) ^ multiply_by_3(
            column[0]) ^ column[1] ^ column[2],
    ]
    return r


# function that does the mix columns operation for a whole AES state
def mix_columns(grid):
    new_grid = [[], [], [], []]
    for i in range(4):
        col = [grid[j][i] for j in range(4)]
        col = mix_column(col)
        for i in range(4):
            new_grid[i].append(col[i])
    # returns the new grid that has been mixed
    return new_grid


# function that adds the round key
def add_round_key(block_grid, key_grid):
    r = []

    # 4 rows in the grid
    for i in range(4):
        r.append([])
        # 4 values on each row
        for j in range(4):
            # XOR each element of the key and the state
            r[-1].append(block_grid[i][j] ^ key_grid[i][j])
    # return post-roundkey state
    return r


# gets the key for the current round
def extract_key_for_round(expanded_key, round):
    return [row[round * 4: round * 4 + 4] for row in expanded_key]


class AES:
    def __init__(self, key, rounds):
        self.key = key
        self.rounds = rounds
        # generate round+1 round keys (if we use 4 rounds, then we'll have 5 keys)
        self.expanded_key = key_schedule(key, rounds)

    def enc(self, data):
        grids = data

        # apply initial key to the AES states before starting the rounds
        temp_grids = []
        round_key = extract_key_for_round(self.expanded_key, 0)

        for grid in grids:
            temp_grids.append(add_round_key(grid, round_key))

        grids = temp_grids

        # iterate through all the rounds except for the last round, i.e. 3 rounds
        for round in range(1, self.rounds):
            temp_grids = []

            for grid in grids:
                # the first function is the subBytes
                sub_bytes_step = [[lookup(val) for val in row] for row in grid]
                # then it is the shiftRows
                shift_rows_step = [shift_row(
                    sub_bytes_step[i], i) for i in range(4)]
                # then we do the mixColumns
                mix_column_step = mix_columns(shift_rows_step)
                # then we add the round key
                round_key = extract_key_for_round(self.expanded_key, round)
                add_sub_key_step = add_round_key(mix_column_step, round_key)
                temp_grids.append(add_sub_key_step)

            grids = temp_grids

        # for the final special round we do everything again excpet for the mixColumns function
        temp_grids = []

        for grid in grids:
            # subBytes
            sub_bytes_step = [[lookup(val) for val in row] for row in grid]
            # shiftRows
            shift_rows_step = [shift_row(
                sub_bytes_step[i], i) for i in range(4)]
            # add the last round key
            round_key = extract_key_for_round(self.expanded_key, self.rounds)
            self.last_round_key = round_key
            add_sub_key_step = add_round_key(shift_rows_step, round_key)
            temp_grids.append(add_sub_key_step)

        grids = temp_grids

        # return data in a list of hexadecimal list for each encrypted plaintext
        int_stream = []

        for grid in grids:
            temp = []
            for column in range(4):
                for row in range(4):
                    temp.append(grid[row][column])
            temp = binascii.hexlify(bytes(temp))
            int_stream.append([temp])

        return int_stream


def main():
    # key as int
    # 7901AB25EFA98FE78CB897D79807AABE
    key = 160845251084489498292973467386516056766
    # convert key to bytearray
    key = bytearray.fromhex('{:032x}'.format(key))
    # create a new AES instance
    aes = AES(key, 4)

    # proof that the active bit of an delta-set xor'ed is zero
    assert (0x00 ^ 0x01 ^ 0x02 ^ 0x03) == 0
    assert (0x00 ^ 0x01 ^ 0x02 ^ 0x03 ^ 0x04 ^ 0x05 ^ 0x06 ^ 0x07) == 0
    assert (0x00 ^ 0x01 ^ 0x02 ^ 0x03 ^ 0x04 ^ 0x05 ^ 0x06 ^ 0x07 ^ 0x08 ^ 0x09 ^ 0x0a ^ 0x0b ^ 0x0c ^ 0x0d ^ 0x0e ^ 0x0f) == 0

    # proof that the inactive bit of a delta-set xor'ed (aka the same bit xor'ed in 2^n times) is zero
    assert (0x01 ^ 0x01 ^ 0x01 ^ 0x01) == 0
    assert (0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01) == 0
    assert (0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01 ^ 0x01) == 0

    # guess the last round key
    guessed_last_round_key = []
    # iterate through each index in key: 0-15
    for j in range(16):
        key_byte = []
        res = aes.enc(delta_set())
        # iterate through all possible values: 0-255
        for i in range(256):
            # reverse last round with key byte candidate
            guessed_key_byte = rev_last_round(i, j, res)
            # check if key byte candidate upholds delta-set xor rule: all values xor'ed must be zero
            if check_guess(guessed_key_byte):
                key_byte.append(i)
        # check if multiple correct candidates are found
        if len(key_byte) > 1:
            # do until one candidate is left, which is the correct key byte for that given index
            while len(key_byte) != 1:
                temp = []
                # each new encryption with a delta_set uses a different number in passive bytes
                res = aes.enc(delta_set())
                # check if the possible candidates upholds the delta_set xor rule with new delta_sets
                for k in range(len(key_byte)):
                    guessed_key_byte = rev_last_round(key_byte[k], j, res)
                    if check_guess(guessed_key_byte):
                        temp.append(key_byte[k])
                key_byte = temp
        # append correct key byte to list
        guessed_last_round_key.append(key_byte[0])

    # last round key reformat
    temp = []
    for i in range(4):
        for j in range(4):
            temp.append(aes.last_round_key[j][i])
    aes.last_round_key = temp

    # check if guessed key is last round key
    assert guessed_last_round_key == aes.last_round_key

    # retrieve key from the 4 round keys
    for i in range(3, -1, -1):
        # the last 12 bytes of the previous round key can be found by XOR'ing the bytes of the current round key
        guessed_key = []
        for j in range(15, 3, -1):
            guessed_key.append(guessed_last_round_key[j] ^ guessed_last_round_key[j - 4])
        guessed_key.reverse()
        
        # the first four bytes of the previous round key can be found by doing the key expansion on the last four bytes of the previous round key and xoring them with the first four bytes of the current round key
        rcon = [[1, 0, 0, 0]]
        for _ in range(1, 4):
            rcon.append([rcon[-1][0] * 2, 0, 0, 0])
            if rcon[-1][0] > 0x80:
                rcon[-1][0] ^= 0x11b
        
        # shiftRow, subBytes and applying round constant on the first 4 bytes of the previous round key
        last_column = guessed_key[8:12]
        last_column_shift_row = shift_row(last_column)
        last_column_sbox_step = [lookup(b) for b in last_column_shift_row]
        last_column_rcon_step = [last_column_sbox_step[s]
                                ^ rcon[i][s] for s in range(len(last_column_shift_row))]
        
        # XOR'ing the manipulated last four bytes of the previous round key with the first four bytes of the current round key to get the first four bytes of the previous round key
        guessed_key.reverse()
        for k in range(3, -1, -1):
            guessed_key.append(guessed_last_round_key[k] ^ last_column_rcon_step[k])
        guessed_key.reverse()
        guessed_last_round_key = guessed_key
    obtained_key = guessed_last_round_key

    # check if retrieved key is the same as the original key
    assert bytearray(obtained_key) == key
    if bytearray(obtained_key) == key:
        print("Attack successful!")

if __name__ == "__main__":
    main()
