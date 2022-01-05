# Daimeun Praytor


import random
import time
import re


# Takes in the plain text and key and returns the encrypted string.
def encrypt(plainText, keyVal):
    # Creates an array that stores 8 character strings
    binaryBlock = re.findall('.{1,8}', plainText)

    # Fills the last block with trailing spaces so it is 8 characters.
    count = 0
    for block in binaryBlock:
        if len(block) < 8:
            binaryBlock[count] = block.ljust(8, ' ')

        count += 1

    # Converts each of the 8 characters in each block into its binary ascii value and pads with 0's to 8 places.
    count = 0
    for block in binaryBlock:
        binaryBlock[count] = ''.join(format(ord(i), 'b').zfill(8) for i in block)
        count += 1

    # Creates an array of 16 round keys.
    roundKeys = getRoundKeys(keyVal)

    # Runs the DES implementation on each block and concatenates them to cypher text.
    #cypherText = []
    cypherText = ''
    for block in binaryBlock:
        curCypherBin = DES(str(block), roundKeys)
        cypherText = cypherText + getASCII(curCypherBin)

    return cypherText


# Takes in cypher text and a key and returns the decrypted string.
def decrypt(cypherText, keyVal):
    # Creates an array that stores 8 character strings
    binaryBlock = re.findall('.{1,8}', cypherText)

    # Converts each of the 8 characters in each block into its binary ascii value and pads with 0's to 8 places.
    count = 0
    for block in binaryBlock:
        binaryBlock[count] = ''.join(format(ord(i), 'b').zfill(8) for i in block)
        count += 1

    # Creates an array of 16 round keys.
    roundKeysTemp = getRoundKeys(keyVal)
    roundKeys = []
    count = 15
    for i in range(len(roundKeysTemp)):
        roundKeys.append(roundKeysTemp[count])
        count -= 1

    # Runs the DES implementation on each block and concatenates them to cypher text.
    # cypherText = []
    decypherText = ''
    for block in binaryBlock:
        curDecypherBin = DES(str(block), roundKeys)
        decypherText = decypherText + getASCII(curDecypherBin)

    return decypherText


# Converts a 64 bit binary number into ASCII
def getASCII(binary):
    splitBinary = re.findall('.{1,8}', binary)
    result = ""
    for word in splitBinary:
        currentDec = int(word, 2)
        result = result + chr(currentDec)

    return result


# Takes in the number to be permutated the array to map the permutation and the number of bits the new value will have
def permutate(number, permMap, numBits):
    # Creates a permuted string of numbers
    permuteNum = ''
    for mapIndex in range(0, numBits):
        permuteNum = permuteNum + number[permMap[mapIndex] - 1]

    return permuteNum


# Generates the 16 round keys
def getRoundKeys(keyVal):
    # The shift array is used to tell each sub-key how many bits to shift left.
    shifts = [1, 1, 2, 2,
              2, 2, 2, 2,
              1, 2, 2, 2,
              2, 2, 2, 1]

    # This is the array that is used to permutate and compress the key to 48 bits.(PC-2)
    keyCompressionMap = [14, 17, 11, 24, 1, 5,
                         3, 28, 15, 6, 21, 10,
                         23, 19, 12, 4, 26, 8,
                         16, 7, 27, 20, 13, 2,
                         41, 52, 31, 37, 47, 55,
                         30, 40, 51, 45, 33, 48,
                         44, 49, 39, 56, 34, 53,
                         46, 42, 50, 36, 29, 32]

    # Generates the 16 round keys
    leftKey = keyVal[0:28]
    rightKey = keyVal[28:56]
    roundKeys = []
    for i in range(0, 16):
        # Shifts both key halves
        leftKey = shiftLeft(leftKey, shifts[i])
        rightKey = shiftLeft(rightKey, shifts[i])

        # Combines the two halves
        newKey = leftKey + rightKey

        # Creates a round key that is compressed to 48 bits
        roundKey = permutate(newKey, keyCompressionMap, 48)

        # Adds the round Key to the list.
        roundKeys.append(roundKey)

    return roundKeys


# Shifts the given bits but the number of shifts given
def shiftLeft(value, numShifts):
    # Shifts the bits in the given value left by numShifts number of times.
    shiftedVal = ''
    for i in range(numShifts):
        for j in range(1, len(value)):
            shiftedVal = shiftedVal + value[j]

        # Accounts for the leftmost bit shifting.
        shiftedVal = shiftedVal + value[0]
        value = shiftedVal
        shiftedVal = ''

    return value


# Implements the data encryption standard on the given number
def DES(number, roundKeys):
    # These are the various arrays used in the DES function for permutations.
    initPermMap = [58, 50, 42, 34, 26, 18, 10, 2,
                   60, 52, 44, 36, 28, 20, 12, 4,
                   62, 54, 46, 38, 30, 22, 14, 6,
                   64, 56, 48, 40, 32, 24, 16, 8,
                   57, 49, 41, 33, 25, 17, 9, 1,
                   59, 51, 43, 35, 27, 19, 11, 3,
                   61, 53, 45, 37, 29, 21, 13, 5,
                   63, 55, 47, 39, 31, 23, 15, 7]

    expansionMap = [32, 1, 2, 3, 4, 5, 4, 5,
                    6, 7, 8, 9, 8, 9, 10, 11,
                    12, 13, 12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21, 20, 21,
                    22, 23, 24, 25, 24, 25, 26, 27,
                    28, 29, 28, 29, 30, 31, 32, 1]

    interPermMap = [16, 7, 20, 21,
                    29, 12, 28, 17,
                    1, 15, 23, 26,
                    5, 18, 31, 10,
                    2, 8, 24, 14,
                    32, 27, 3, 9,
                    19, 13, 30, 6,
                    22, 11, 4, 25]

    finalPermMap = [40, 8, 48, 16, 56, 24, 64, 32,
                    39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25]

    number = permutate(str(number), initPermMap, 64)

    # Splits the 64 bit sting into 32 bit sections
    left = number[0:32]
    right = number[32:64]
    nextLeft = ""
    for i in range(0, 16):
        # Sets the next left to the current right
        nextLeft = right

        # Preforms expansion permutation on the right half to expand to 48 bits
        rightExpanded = permutate(right, expansionMap, 48)

        # Preforms XOR on the right bits and the current round key
        rightXOR = XOR(rightExpanded, roundKeys[i])

        # Preforms S-box function to reduce back down to 32 bits
        rightReduced = sBox(rightXOR)

        # Intermediate permutation
        rightPermute = permutate(rightReduced, interPermMap, 32)

        # XOR the permuted right side and the left side to get the right side for the next round
        finalRight = XOR(left, rightPermute)

        # Sets the next rounds right to the final permuted bits
        right = finalRight
        # Sets the starting right to the left bits for the next round
        left = nextLeft

    # Combines the left and right side.
    number = right + left

    # Preforms the final permutation
    number = permutate(number, finalPermMap, 64)

    return number


# Preforms XOR operation on the two given inputs and outputs the result
def XOR(right, roundKey):
    # Compares the right bits to the roundKey bits with xor
    newRight = ''
    for i in range(len(right)):
        if right[i] == roundKey[i]:
            newRight = newRight + "0"
        else:
            newRight = newRight + "1"

    return newRight


# Reduces a 48 bit input to 32 bits (I used all 8 s-boxes as opposed to using one 8 times.)
def sBox(right):
    # This is the array for all 8 of the s-boxes.
    sBoxMap = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

               [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

               [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

               [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

               [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

               [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

               [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

               [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

    # Reduces the 48 bit input to 32 bits.
    reducedRight = ""
    for subArray in range(0, 8):
        # Row is the outer two of the six bits
        row = int(right[subArray * 6] + right[subArray * 6 + 5])
        # Column is the inner four of the six bits
        column = int(right[subArray * 6 + 1] + right[subArray * 6 + 2] + right[subArray * 6 + 3] + right[subArray * 6 + 4])

        # Gets the decimal value from the binary
        row = getDecimal(str(row))
        column = getDecimal(str(column))

        # Gets the corresponding value from the sBoxMap and converts it to binary (4 bits)
        # After all 8 runs this creates the new reduced 32 bit binary number.
        mapVal = sBoxMap[subArray][row][column]
        mapVal = getBinary(mapVal)
        reducedRight = reducedRight + str(mapVal)

    return reducedRight


# Transforms a binary number input to decimal
def getDecimal(binaryNum):
    converted = int(binaryNum, 2)
    return converted


# Transforms a decimal number into a 4 bit binary number (max decimal input is 15)
def getBinary(binaryNum):
    return bin(binaryNum).replace("0b", "").zfill(4)


if __name__ == "__main__":

    print("DES Implementation:")

    plainText = ""
    while plainText != "Exit":

        # Creates a new seed for the key based on current system time
        random.seed(time.time())
        # Generates a random 56 bit key
        key = random.getrandbits(56)
        # Converts the key to binary fills with 0's because sometimes it is given less than 56 bits.
        key = format(key, "b").zfill(56)

        # Gets the users input
        plainText = input("Enter text to encrypt (\"Exit\" to quit):")
        test = re.findall('.{1,8}', plainText)

        # If the user enters "Exit" continue to break out of the loop
        if plainText == "Exit":
            continue

        cypherText = encrypt(plainText, key)

        print("Encrypted text:  ", cypherText)
        decryptedText = decrypt(cypherText, key)
        print("Decrypted text:  ", decryptedText)
