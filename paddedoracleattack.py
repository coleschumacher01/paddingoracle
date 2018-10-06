import binascii
import cbc
import paddingoracle
import sys

#Performs bitwise XOR of a single byte from two blocks at the same index
def xorByte(block1, block2, index):
    #Get hex bytes
    byte1 = block1[2*index:2*(index + 1)]
    byte2 = block2[2*index:2*(index + 1)]

    #convert to int
    byte1 = int(byte1, 16)
    byte2 = int(byte2, 16)

    #XOR
    byte = byte1 ^ byte2
    
    #Convert back to hex string
    byte = format(byte, 'x')
    if (len(byte) < 2):
        byte = '0' + byte
    
    return byte

#Performs bitwise XOR on all bytes in two blocks
def xorBlock(block1, block2):
    newblock = ''
    for i in range(16):
        newblock += xorByte(block1, block2, i)

    return newblock


#Increments a single byte in a block
def incrementByte(s, index):
    #Get hex byte
    byte = s[2*index:2*(index + 1)]
    
    #Convert to int and increment
    byte = int(byte, 16) + 1
    
    #COnvert back to hex string
    byte = format(byte, 'x')
    if (len(byte) < 2):
        byte = '0' + byte

    #Return entire block with incremented byte at index
    return s[:2*index] + byte + s[2*(index + 1):]

#Brute forces all combinations of a byte at index in block1 until padding oracle says padding is valid
def bruteforceByte(block1, block2, index):
    while(not paddingoracle.checkPadding(block1 + block2, cbc.iv)):
        block1 = incrementByte(block1, index)

    return block1

#Determines the length of the padding 
def checkPaddingLength(garbage, block, paddingLength):
    #Case where the whole block is padded
    if paddingLength == 16:
        return 16
    #Case where paddingLength is already correct
    if (paddingoracle.checkPadding(incrementByte(garbage, 16 - (paddingLength + 1)) + block, cbc.iv)):
            return paddingLength
    else:
        #Determine padding length - point where incrementing a byte still reports valid padding
        i = paddingLength + 1
        while i < 16:
            if (paddingoracle.checkPadding(incrementByte(garbage, 16 - (i + 1)) + block, cbc.iv)):
                return i
            else:
                i = i + 1

#Calculate the new values of garbage and ciphertext with the new padding length
def nextIteration(garbage, ciphertext, paddingLength):
    #Get paddingLength as hex string
    padByte = format(paddingLength, 'x')
    if (len(padByte) < 2):
        padByte = '0' + padByte
    
    #Create block with padding
    padblock = ''
    for i in range(16 - paddingLength):
        padblock += '00'

    for i in range(paddingLength):
        padblock += padByte

    #Get new ciphertext
    ciphertext = xorBlock(garbage, padblock)

    #Get next paddingLength as hex string
    padByte = format(paddingLength + 1, 'x')
    if (len(padByte) < 2):
        padByte = '0' + padByte
    
    #Create block with new padding
    padblock = ''
    for i in range(16 - paddingLength):
        padblock += '00'

    for i in range(paddingLength):
        padblock += padByte

    #Get new garbage
    garbage = xorBlock(ciphertext, padblock)
 
    return garbage, ciphertext

#Performs padding oracle attack on the given block
def attack(block):
    garbage = '00000000000000000000000000000000'
    ciphertext = '00000000000000000000000000000000'

    #Bruteforce bytes in garbage array until we have gotten garbage array that
    #produces a block with 16 bytes of padding
    paddingLength = 1
    while paddingLength <= 16:
        #Bruteforce and get current paddingLength
        garbage = bruteforceByte(garbage, block, 16 - paddingLength)
        paddingLength = checkPaddingLength(garbage, block, paddingLength)
        
        #Update garbage, ciphertext and paddingLength
        garbage, ciphertext = nextIteration(garbage,ciphertext, paddingLength)
        paddingLength = paddingLength + 1

    return ciphertext

if __name__ == "__main__":
    ciphertext = sys.argv[1]

    #Split string into blocks
    blocks = [ciphertext[i:i + 2 * 16] for i in range(0, len(ciphertext), 2 * 16)]
    toprintHex = ''
    toprintPlaintext = ''

    #Decrypt all blocks using padding oracle attack
    for i in range(len(blocks)):
        #Use IV for first block
        if (i == 0):
            lastcipher = binascii.hexlify(cbc.iv)
        else:
            lastcipher = blocks[i - 1]

        toprintHex += xorBlock(attack(blocks[i]), lastcipher)
    print('Hex output: ' + toprintHex)
    print('Plaintext output: ' + binascii.b2a_qp(binascii.unhexlify(toprintHex)))
