n = 16 # word size: 16 24 32 48 64
m = 4 # number of key words
      # 4         if n = 16
      # 3 or 4    if n = 24 or 32
      # 2 or 3    if n = 48
      # 2, 3 or 4 if n = 64

z = [[1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0],
     [1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0],
     [1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1],
     [1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1],
     [1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1]]

(T, j) = (32,0)
# (T, j) = (32,0)                     if n = 16
# (T, j) = (36,0) or (36,1)           if n = 24, m = 3 or 4
# (T, j) = (42,2) or (44,3)           if n = 32, m = 3 or 4
# (T, j) = (52,2) or (54,3)           if n = 48, m = 2 or 3
# (T, j) = (68,2), (69,3), or (72,4)  if n = 64, m = 2, 3, or 4


def S(m, d):
    if d >= 0:
        return (((m << d) ^  (m >> (n-d))) & (2**n-1))
    else:
        return (((m >> -d) ^  (m << (n+d))) & (2**n-1))


class Simon:
    k = [] # the key

    def keyschedule(self, key):
        self.k = list(key)
        for i in range(m, T):
            tmp = S(self.k[i-1], -3)
            if m == 4:
                tmp ^= self.k[i-3]
            tmp ^= S(tmp, -1)
            self.k.append((~self.k[i-m] & (2**n-1)) ^ tmp ^ z[j][(i-m) % 62] ^ 3)
        return
      
    def __init__(self, key):
        self.keyschedule(key)

    def encrypt(self, plaintext):
        p = [plaintext[0], plaintext[1]]

        for i in range(T):
            tmp = p[1]
            p[1] = p[0] ^ S(p[1],1) & S(p[1],8) ^ S(p[1],2) ^ self.k[i]
            p[0] = tmp
        return p

    def decrypt(self, ciphertext):
        p = [ciphertext[0], ciphertext[1]]

        p[0], p[1] = p[1], p[0]
        for i in range(T-1, -1, -1):
            tmp = p[1]
            p[1] = p[0] ^ S(p[1],1) & S(p[1],8) ^ S(p[1],2) ^ self.k[i]
            p[0] = tmp
        p[0], p[1] = p[1], p[0]
        return p


if __name__ == "__main__":
    cipher = Simon((0x0100, 0x0908, 0x1110, 0x1918))
    p  =  [0x6877, 0x6565]
    print(hex(p[1]), hex(p[0]))
    p = cipher.encrypt(p)
    assert p[0] == 0xe9bb
    assert p[1] == 0xc69b
    print(hex(p[1]), hex(p[0]))
    p = cipher.decrypt(p)
    print(hex(p[1]), hex(p[0]))

