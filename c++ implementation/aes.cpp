#include <iostream>
#include <array>
#include <string>
#include <random>
#include <set>
#include <algorithm>
#include <time.h>

typedef std::array<uint8_t, 4> Word;  // A word is a Column of 4 bytes
typedef std::array<Word, 4> Block; // A block consists of 4 columns (4 words basically)
typedef std::array<std::array<std::set<uint8_t>, 4>, 4> GuessBlock;

void printBlock(Block block) {
    for(int j = 0; j < 4; ++j) {
        for(int i = 0; i < 4; ++i) {
            std::cout << std::hex << int(block[i][j]);
            std::cout << " ";
        }
        std::cout << "\n";
    }
    std::cout << "\n";
}

////////////////////////////////////////

// LOOKUP TABLES //

/* AES S-Box */
uint8_t S[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

/* AES Inverse S-Box */
uint8_t SI[] = { 
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D 
};
/* Return the index of a byte for the lookup tables */
int lookUpIndex(uint8_t byte) {
    int least_significant_4bits = (byte & 0x0F);
    int most_significant_4bits = ((byte >> 4) & 0x0F);
    int idx = most_significant_4bits * 16 + least_significant_4bits;
    return idx;
}
/* Substitute byte according to the S-box lookup table */
uint8_t subByte(uint8_t byte) {
    return S[lookUpIndex(byte)];
}
/* Substitute byte according to the inverted S-box lookup table */
uint8_t inv_subByte(uint8_t byte) {
    return SI[lookUpIndex(byte)];
}

////////////////////////////////////////

// MATH STUFF //

/* Add two numbers in the GF(2^8) finite field */
uint8_t gadd(uint8_t a, uint8_t b) {
	return a ^ b;
}

/* Multiply two numbers in the GF(2^8) finite field defined 
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * using the Russian Peasant Multiplication algorithm
 * (the other way being to do carry-less multiplication followed by a modular reduction)
 */
uint8_t gmul(uint8_t a, uint8_t b) {
	uint8_t p = 0; /* the product of the multiplication */
	while (a && b) {
        if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
            p ^= a; /* since we're in GF(2^m), addition is an XOR */

        if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
            a = (a << 1) ^ 0x11b; //0x1b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible */
        else
            a <<= 1; /* equivalent to a*2 */
        b >>= 1; /* equivalent to b // 2 */
	}
	return p;
}


////////////////////////////////////////

// KEY EXPANSION FUNCTIONS //

Word xorWords(Word a, Word b) {
    return {a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]};
}

Word rotWord(Word bytes) {
    return { bytes[1], bytes[2], bytes[3], bytes[0] };
}

Word subWord(Word bytes) {
    return { subByte(bytes[0]), subByte(bytes[1]), subByte(bytes[2]), subByte(bytes[3]) };
}

Word inv_subWord(Word bytes) {
    return { inv_subByte(bytes[0]), inv_subByte(bytes[1]), inv_subByte(bytes[2]), inv_subByte(bytes[3]) };
}

template<const int number_of_keys>
std::array<Block, number_of_keys> keyExpansion(Block key) {
    std::array<Block, number_of_keys> roundKeys;
    roundKeys[0] = key;
    uint8_t rcon = 0x01;

    for(int round = 1; round < number_of_keys; ++round) {
        Word firstCol = xorWords(xorWords(subWord(rotWord(roundKeys[round-1][3])), roundKeys[round-1][0]), {rcon, 0x00, 0x00, 0x00});
        Word secondCol = xorWords(firstCol, roundKeys[round-1][1]);
        Word thirdCol = xorWords(secondCol, roundKeys[round-1][2]);
        Word fourthCol = xorWords(thirdCol, roundKeys[round-1][3]);

        roundKeys[round] = { firstCol, secondCol, thirdCol, fourthCol };

        rcon = (rcon<<1) ^ (0x11b & -(rcon>>7));
    }

    return roundKeys;
}

template<const int number_of_keys>
std::array<Block, number_of_keys> inv_keyExpansion(Block key) {
    std::array<Block, number_of_keys> roundKeys;
    roundKeys[number_of_keys - 1] = key;

    uint8_t rcon = 0x01;
    std::array<Word, number_of_keys> rcons;
    for(int i = 0; i < number_of_keys; ++i) {
        rcons[i] = {rcon, 0x00, 0x00, 0x00};
        rcon = (rcon<<1) ^ (0x11b & -(rcon>>7));
    }

    for(int round = number_of_keys - 2; round >= 0; --round) {
        Word fourthCol = xorWords(roundKeys[round+1][3], roundKeys[round+1][2]);
        Word thirdCol = xorWords(roundKeys[round+1][2], roundKeys[round+1][1]);
        Word secondCol = xorWords(roundKeys[round+1][1], roundKeys[round+1][0]);
        Word firstCol = xorWords(xorWords(roundKeys[round+1][0], rcons[round]), subWord(rotWord(fourthCol)));

        roundKeys[round] = { firstCol, secondCol, thirdCol, fourthCol };
    }

    return roundKeys;
}

//////////////////////////

// AES ROUNDS FUNCTIONS //

Block createBlock(Word a, Word b, Word c, Word d) {
    return {a, b, c, d};
}

Block subBytes(Block b) {
    return {subWord(b[0]), subWord(b[1]), subWord(b[2]), subWord(b[3])};
}

Block inv_subBytes(Block b) {
    return {inv_subWord(b[0]), inv_subWord(b[1]), inv_subWord(b[2]), inv_subWord(b[3])};
}

Block shiftRows(Block b) {
    Block newBlock;
    for(int j = 0; j < 4; ++j) {
        for(int i = 0; i < 4; ++i) {
            newBlock[i][j] = b[(i + j) % 4][j];
        }
    }
    return newBlock;
}

Block inv_shiftRows(Block b) {
    Block newBlock;
    for(int j = 0; j < 4; ++j) {
        for(int i = 0; i < 4; ++i) {
            newBlock[i][j] = b[(4 + i - j) % 4][j];
        }
    }
    return newBlock;
}

Word mixColumn(Word w) {
    Word newWord;
    newWord[0] = gmul(0x02, w[0]) ^ gmul(0x03, w[1]) ^ gmul(0x01, w[2]) ^ gmul(0x01, w[3]);
    newWord[1] = gmul(0x01, w[0]) ^ gmul(0x02, w[1]) ^ gmul(0x03, w[2]) ^ gmul(0x01, w[3]);
    newWord[2] = gmul(0x01, w[0]) ^ gmul(0x01, w[1]) ^ gmul(0x02, w[2]) ^ gmul(0x03, w[3]);
    newWord[3] = gmul(0x03, w[0]) ^ gmul(0x01, w[1]) ^ gmul(0x01, w[2]) ^ gmul(0x02, w[3]);
    return newWord;
}

/* The M^-1 matrix is exactly M^3 matrix
 * Thus we can either multiply the mixed matrix 3 times by the original M matrix
 * Or calculate the M^3 matrix (can be found on wikipedia)
 * and use that matrix for multiplication.
 */
Word inv_mixColumn(Word w) {
    Word newWord;
    newWord[0] = gmul(0x0e, w[0]) ^ gmul(0x0b, w[1]) ^ gmul(0x0d, w[2]) ^ gmul(0x09, w[3]);
    newWord[1] = gmul(0x09, w[0]) ^ gmul(0x0e, w[1]) ^ gmul(0x0b, w[2]) ^ gmul(0x0d, w[3]);
    newWord[2] = gmul(0x0d, w[0]) ^ gmul(0x09, w[1]) ^ gmul(0x0e, w[2]) ^ gmul(0x0b, w[3]);
    newWord[3] = gmul(0x0b, w[0]) ^ gmul(0x0d, w[1]) ^ gmul(0x09, w[2]) ^ gmul(0x0e, w[3]);
    return newWord;
}

Block mixColumns(Block b) {
    Block newBlock;
    for(int i = 0; i < 4; ++i) newBlock[i] = mixColumn(b[i]);
    return newBlock;
}

Block inv_mixColumns(Block b) {
    Block newBlock;
    for(int i = 0; i < 4; ++i) newBlock[i] = inv_mixColumn(b[i]);
    return newBlock;
}

Block convertToBlock(std::string text) {
    Block newBlock;
    for(int i = 0; i < 4; ++i) {
        for(int j = 0; j < 4; ++j) {
            newBlock[i][j] = text[i*4 + j];
        }
    }

    return newBlock;
}

std::string convertToString(Block block) {
    std::string text = "";
    for(const Word& word: block) {
        for(const uint8_t& byte: word) {
            text += byte;
        }
    }
    return text;
} 

Block addRoundKey(Block b, Block roundkey) {
    Block newBlock;

    for(int i = 0; i < 4; ++i) newBlock[i] = xorWords(b[i], roundkey[i]);

    return newBlock;
}

template<const int number_of_rounds = 10>
class AES {
private:
    Block key;
    const int rounds;
    std::array<Block, number_of_rounds + 1> round_keys;

public:
    AES(Block key): rounds(number_of_rounds), key(key)  {
        round_keys = keyExpansion<number_of_rounds + 1>(key);
    }

    void printKeys() {
        for(const auto& key : round_keys) printBlock(key);
    }

    Block encrypt(Block originalBlock) {
        Block encryptedBlock = addRoundKey(originalBlock, round_keys[0]);
        for(int i = 1; i < rounds; ++i) {
            encryptedBlock = addRoundKey(mixColumns(shiftRows(subBytes(encryptedBlock))), round_keys[i]);
        }
        encryptedBlock = addRoundKey(shiftRows(subBytes(encryptedBlock)), round_keys[rounds]);
        return encryptedBlock;
    }

    Block decrypt(Block encryptedBlock) {
        Block decryptedBlock = inv_subBytes(inv_shiftRows(addRoundKey(encryptedBlock, round_keys[rounds])));
        for(int i = 1; i < rounds; ++i) {
            decryptedBlock = inv_subBytes(inv_shiftRows(inv_mixColumns(addRoundKey(decryptedBlock, round_keys[rounds-i]))));
        }
        decryptedBlock = addRoundKey(decryptedBlock, round_keys[0]);
        return decryptedBlock;
    }
};

typedef AES<10> AES_128;

//////////////////////////

// SQUARE ATTACK FUNCTIONS //
template<int rounds>
std::array<Block, 256> generateDelta(AES<rounds>& aes) {
    uint8_t passive_byte = rand()%256;
    std::array<Block, 256> delta;

    uint8_t i = 0x00;
    do {
        Block b = createBlock({i, passive_byte, passive_byte, passive_byte}, 
                              {passive_byte, passive_byte, passive_byte, passive_byte},
                              {passive_byte, passive_byte, passive_byte, passive_byte},
                              {passive_byte, passive_byte, passive_byte, passive_byte});
        delta[i] = aes.encrypt(b);
        ++i;
    } while (i != 0x00);

    return delta;
}

uint8_t reverseLastRoundAtPos(int columnPos, int rowPos, uint8_t guess, Block encryptedBlock) {
    uint8_t encryptedByte = encryptedBlock[columnPos][rowPos];
    encryptedByte ^= guess;
    encryptedByte = inv_subByte(encryptedByte);

    return encryptedByte;
}

bool checkGuess(std::array<Block, 256> delta, int columnPos, int rowPos, uint8_t guess) {
    uint8_t res = 0x00;
    for(const Block& block: delta) {
        res ^= reverseLastRoundAtPos(columnPos, rowPos, guess, block);
    }
    return res == 0x00;
}

void squareAttack(AES<4>& aes) {
    GuessBlock guesses;
    Block lastRoundKey;
    bool keyFound = false;

    while(!keyFound) {
        keyFound = true;
        std::array<Block, 256> delta = generateDelta(aes);

        for(int i = 0; i < 4; ++i) {
            for(int j = 0; j < 4; ++j) {
                // if first round or if we still have multiple guesses
                if (guesses[i][j].size() != 1) {
                    keyFound = false;
                    std::set<uint8_t> currentCorrectGuesses;

                    // going over all possible byte guesses and storing them if they are valid candidates
                    uint8_t guess = 0x00;
                    do {
                        if (checkGuess(delta, i, j, guess)) currentCorrectGuesses.insert(guess);
                        guess++;
                    } while (guess != 0x00);

                    // if no guesses have been found yet, store them
                    if (guesses[i][j].size() == 0) guesses[i][j] = currentCorrectGuesses;
                    else {
                        // if it is not the first round, take intersection with previous sets
                        std::set<uint8_t> intersection;
                        set_intersection(currentCorrectGuesses.begin(), 
                                        currentCorrectGuesses.end(), 
                                        guesses[i][j].begin(),
                                        guesses[i][j].end(), 
                                        std::inserter(intersection, intersection.begin())
                                        );
                        guesses[i][j] = intersection;
                    }
                // if we only have one guess, store it as final
                } else {
                    lastRoundKey[i][j] = *(guesses[i][j].begin());
                }
            }
        }
    }
    std::array<Block, 5> roundKeys = inv_keyExpansion<5>(lastRoundKey);

    for (const auto& key : roundKeys) printBlock(key);
}


int main() {
    srand(time(NULL));
    Block key = createBlock({0x2b, 0x7e, 0x15, 0x16}, 
                            {0x28, 0xae, 0xd2, 0xa6},
                            {0xab, 0xf7, 0x15, 0x88},
                            {0x09, 0xcf, 0x4f, 0x3c});
    /*
    AES_128 aes = AES_128(key);

    Block encrypted = aes.encrypt(convertToBlock("theblockbreakers"));
    Block decrypted = aes.decrypt(encrypted);
    std::cout << convertToString(decrypted) << "\n"; */

    // ATTACK

    AES<4> aes_4 = AES<4>(key);
    aes_4.printKeys();
    squareAttack(aes_4);

    return 0;
}