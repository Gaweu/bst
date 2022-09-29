from scipy.io import wavfile
import numpy as np
import binascii

def decimalToBinary(n):
    n = bin(n).replace("0b", "")
    if len(n) != 16:
        n = (16-len(n))*"0" + n
    if "-" in n:
        n = n.replace("-", "")
        n = "-" + n
    return n

def calculateXor(bit1, bit2, bit3):
    if bit1 == "1":
        bit1 = True
    else:
        bit1 = False
    
    if bit2 == "1":
        bit2 = True
    else:
        bit2 = False

    if bit3 == "1":
        bit3 = True
    else:
        bit3 = False

    return bit1 ^ bit2 ^ bit3

def generateRandom(max=4096):
    data = wavfile.read('sample.wav')
    channel = data[:, 0]
    combinedBits = []
    S = ""
    for byte in channel:
        bits = decimalToBinary(byte)
        combinedBits.append(True & calculateXor(
            bits[-1], bits[-2], bits[-3]))
        if (len(combinedBits) == 8):
            combinedBits = np.array(combinedBits)
            S += str(int(np.packbits(combinedBits)))
            if len(S) >= max and len(S) % 2 == 0:
                break
            combinedBits = []


    S = binascii.unhexlify(S)  
    return S

