from simon import Simon
from generate_mitm_sets import generateData
import time
from memory_profiler import profile

class MITM:
  def __init__(self):
    self.possible_key1 = []
    self.possible_key2 = []

  def _stringToList(self, string):
    string_parts = string.split(" ")
    return [int(string_num, 10) for string_num in string_parts]

  def _listToString(self, ls):
    initialStr = str(ls[0])
    for i in range(1, len(ls)):
      initialStr += f" {ls[i]}"
    return initialStr

  @profile
  def breakKey(self, keySize, dict):
    cipherTexts = dict["ciphertext"]
    plainTexts = dict["plaintext"]
    for i in range(len(cipherTexts)):
      self.updatePossibleKeys(keySize, plainTexts[i], cipherTexts[i])

    return self.possible_key1, self.possible_key2

  def updatePossibleKeys(self, keySize, plaintext, ciphertext):
    if len(self.possible_key1) == 0:
      key1_list = [[i % 2**16, (i // 2**16) % 2**16, 0, 0] for i in range(0, 2**keySize)]
      key2_list = key1_list.copy()
    else:
      key1_list = self.possible_key1.copy()
      key2_list = self.possible_key2.copy()
    self.possible_key1 = []
    self.possible_key2 = []
    table = {}

    for key1 in key1_list:
      cipher = Simon(key1)
      middleState = self._listToString(cipher.encrypt(plaintext))
      table[middleState] = self._listToString(key1)

    for key2 in key2_list:
      cipher = Simon(key2)
      middleState = self._listToString(cipher.decrypt(ciphertext))

      if middleState in table:
        self.possible_key1.append(self._stringToList(table[middleState]))
        self.possible_key2.append(key2)

if __name__ == "__main__":
    mitm = MITM()
    KEY_SIZE = 8

    key1, key2, plaintexts, ciphertexts = generateData(KEY_SIZE)
    pairs_8bits = {
        "plaintext" : plaintexts,
        "ciphertext" : ciphertexts,
    }
    
    print(key1)
    print(key2)

    before = time.time()
    key1, key2 = mitm.breakKey(KEY_SIZE, pairs_8bits)
    after = time.time()
    print(after-before)

    print(key1)
    print(key2)