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


def enc(key, data, delta_flag):
    # local declaration of global last round key field
    global last_round_key
    # check if delta-set is used or not
    if not delta_flag:
        # first we need to pad the data with 0x00 on the most significant bits and break it into blocks of 16
        pad = bytes(16 - len(data) % 16)
        if len(pad) != 16:
            data += pad
        grids = break_in_grids_of_16(data)
    else:
        # if delta_flag is true, encrypt the generated delta-set
        grids = delta_set()
    # generate round keys, as we are only using 4 rounds we only need 5 keys
    expanded_key = key_schedule(key, 4)

    # apply initial key to the AES states before starting the rounds
    temp_grids = []
    round_key = extract_key_for_round(expanded_key, 0)

    for grid in grids:
        temp_grids.append(add_round_key(grid, round_key))

    grids = temp_grids

    # iterate through all the rounds except for the last round, i.e. 3 rounds
    for round in range(1, 4):
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
            round_key = extract_key_for_round(expanded_key, round)
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
        round_key = extract_key_for_round(expanded_key, 4)
        last_round_key = round_key
        add_sub_key_step = add_round_key(shift_rows_step, round_key)
        temp_grids.append(add_sub_key_step)

    grids = temp_grids

    # return data in a list of bytes list for each encrypted plaintext
    int_stream = []

    for grid in grids:
        temp = []
        for column in range(4):
            for row in range(4):
                temp.append(grid[row][column])
        temp = binascii.hexlify(bytes(temp))
        int_stream.append([temp])

    return int_stream


# key as int
# 7901AB25EFA98FE78CB897D79807AABE
key = 160845251084489498292973467386516056766
# convert key to bytearray
key = bytearray.fromhex('{:032x}'.format(key))
# data as int
# 00112233445566778899AABBCCDDEEFF
data = 88962710306127702866241727433142015
# convert data to bytearray
data = bytearray.fromhex('{:032x}'.format(data))
# do the encryption
result = enc(key, data, True)
# print encrypted data
print(*result, sep="\n")

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
    res = enc(key, data, True)
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
            res = enc(key, data, True)
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
        temp.append(last_round_key[j][i])
last_round_key = temp

# check if guessed key is last round key
assert guessed_last_round_key == last_round_key

for i in range(3, -1, -1):
    guessed_key = []
    for j in range(15, 3, -1):
        guessed_key.append(guessed_last_round_key[j] ^ guessed_last_round_key[j - 4])
    guessed_key.reverse()

    rcon = [[1, 0, 0, 0]]
    for _ in range(1, 4):
        rcon.append([rcon[-1][0] * 2, 0, 0, 0])
        if rcon[-1][0] > 0x80:
            rcon[-1][0] ^= 0x11b

    last_column = guessed_key[8:12]
    # Shift row step
    last_column_shift_row = shift_row(last_column)
    # s-box look-up
    last_column_sbox_step = [lookup(b) for b in last_column_shift_row]
    last_column_rcon_step = [last_column_sbox_step[s]
                             ^ rcon[i][s] for s in range(len(last_column_shift_row))]

    guessed_key.reverse()
    for k in range(3, -1, -1):
        guessed_key.append(guessed_last_round_key[k] ^ last_column_rcon_step[k])
    guessed_key.reverse()
    guessed_last_round_key = guessed_key
obtained_key = guessed_last_round_key

assert bytearray(obtained_key) == key
