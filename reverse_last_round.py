import binascii

from s_box import reverse_lookup

def rev_last_round(guess, index, delta_set):
    rev_set = []
    index = index*2
    for elem in delta_set:
        state = elem[0]
        state_byte = binascii.unhexlify(state[index:index+2])
        state_int = int.from_bytes(state_byte, "big")
        rev_add_round_key = state_int ^ guess
        before_sub_byte = reverse_lookup(rev_add_round_key)
        rev_set.append(before_sub_byte)
    return rev_set

def check_guess(rev_bytes):
    res = 0
    for i in rev_bytes:
        res ^= i
    return res == 0
