import binascii

from s_box import reverse_lookup

def rev_last_round(guess, index, delta_set):
    rev_set = []
    #multiply index by 2, as 1 byte is represented by 2 hexadecimals
    index = index*2
    # for each state in the delta-set
    for elem in delta_set:
        state = elem[0]
        # get the corresponding byte of each state in the delta-set
        state_byte = binascii.unhexlify(state[index:index+2])
        state_int = int.from_bytes(state_byte, "big")
        # XOR the byte with the guess
        rev_add_round_key = state_int ^ guess
        # sub the byte using the inverted s-box
        before_sub_byte = reverse_lookup(rev_add_round_key)
        # append the states to the reversed delta-set
        rev_set.append(before_sub_byte)
    return rev_set

# check if the guessed byte is correct
def check_guess(rev_bytes):
    res = 0
    for i in rev_bytes:
        res ^= i
    return res == 0
