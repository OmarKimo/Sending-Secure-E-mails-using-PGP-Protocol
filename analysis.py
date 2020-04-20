import pyDes
import random
import matplotlib.pyplot as plt
from time import time
import os


def encryptMessage(message, key):
    key = key.to_bytes(8, "big")
    DES = pyDes.des(key, pyDes.CBC, IV=b"\0\0\0\0\0\0\0\0",
                    pad=None, padmode=pyDes.PAD_PKCS5)
    return DES.encrypt(message.encode())


def attack(plainText, cipherText):
    key = 0
    while True:
        chosen = key * random.randint(1, 100)
        if encryptMessage(plainText, chosen) == cipherText:
            return chosen
        key += 1


def main():
    plainText = "Security Project 01 - analysis - Omar AbdElkareem"
    KeyLengths = []
    times = []
    for keyBits in range(8, 57, 8):
        key = int.from_bytes(os.urandom(keyBits // 8), "big")
        cipherText = encryptMessage(plainText, key)
        print("inferring the {} bits key......".format(keyBits))
        now = time()
        attack(plainText, cipherText)
        later = time()
        times.append(later - now)
        KeyLengths.append(keyBits)
        print(times)
    # plot the statistics
    plt.title('analysis')
    plt.xlabel('Time to infer the key (seconds)')
    plt.ylabel('Key Length (in bits)')
    plt.plot(times, KeyLengths)
    plt.show()


if __name__ == "__main__":
    main()
