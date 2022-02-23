from simon import Simon
from random import randint

def generateData(size):
    print(f"Key size: {size} bits (the highest {64-size} bits are 0s)")
    key1_as_num = randint(0, 2**size)
    key1 = [key1_as_num % 2**16, (key1_as_num // 2**16) % 2**16, 0, 0]
    key2_as_num = randint(0, 2**size)
    key2 = [key2_as_num % 2**16, (key2_as_num // 2**16) % 2**16, 0, 0]
    print(f"Key 1: {key1[3]:04x} {key1[2]:04x} {key1[1]:04x} {key1[0]:04x}")
    print(f"Key 2: {key2[3]:04x} {key2[2]:04x} {key2[1]:04x} {key2[0]:04x}")
    cipher1 = Simon(key1)
    cipher2 = Simon(key2)
    print("Plaintext-ciphertext pairs:")
    plaintexts = []
    ciphertexts = []
    for _ in range(4):
        plaintext = [randint(0, 2**16), randint(0, 2**16)]
        plaintexts.append(plaintext)
        print(f"[{plaintext[1]:04x} {plaintext[0]:04x}] -> ", end='')
        ciphertext = cipher2.encrypt(cipher1.encrypt(plaintext))
        ciphertexts.append(ciphertext)
        print(f"[{ciphertext[1]:04x} {ciphertext[0]:04x}] ")
    print()
    return key1, key2, plaintexts, ciphertexts


def main():
    sizes = [8, 16, 20, 24, 32]
    for size in sizes:
        generateData(size)


if __name__ == "__main__":
    main()
