import binascii
import cbc
import paddingoracle
import sys

def xorByte(block1, block2, index):
    byte1 = block1[2*index:2*(index + 1)]
    byte2 = block2[2*index:2*(index + 1)]

    byte1 = int(byte1, 16)
    byte2 = int(byte2, 16)

    byte = byte1 ^ byte2
    
    byte = format(byte, 'x')

    if (len(byte) < 2):
        byte = '0' + byte

    
    return byte

def xorBlock(block1, block2):
    newblock = ''
    for i in range(16):
        newblock += xorByte(block1, block2, i)

    return newblock


def incrementByte(s, index):
    byte = s[2*index:2*(index + 1)]
    
    byte = int(byte, 16) + 1
    byte = format(byte, 'x')

    if (len(byte) < 2):
        byte = '0' + byte

    return s[:2*index] + byte + s[2*(index + 1):]

def bruteforceByte(block1, block2, index):
    while(not paddingoracle.checkPadding(block1 + block2, cbc.iv)):
        block1 = incrementByte(block1, index)

    return block1

def checkPaddingLength(garbage, block, paddingLength):
    if paddingLength == 16:
        return 16
    if (paddingoracle.checkPadding(incrementByte(garbage, 16 - (paddingLength + 1)) + block, cbc.iv)):
            return paddingLength
    else:
        i = paddingLength + 1
        while i < 16:
            if (paddingoracle.checkPadding(incrementByte(garbage, 16 - (i + 1)) + block, cbc.iv)):
                return i
            else:
                i = i + 1

def nextIteration(garbage, ciphertext, paddingLength):
    padByte = format(paddingLength, 'x')

    if (len(padByte) < 2):
        padByte = '0' + padByte
    
    padblock = ''
    for i in range(16 - paddingLength):
        padblock += '00'

    for i in range(paddingLength):
        padblock += padByte

    ciphertext = xorBlock(garbage, padblock)


    padByte = format(paddingLength + 1, 'x')

    if (len(padByte) < 2):
        padByte = '0' + padByte
    
    padblock = ''
    for i in range(16 - paddingLength):
        padblock += '00'

    for i in range(paddingLength):
        padblock += padByte

    garbage = xorBlock(ciphertext, padblock)
 
    return garbage, ciphertext


def attack(block):
    garbage = '00000000000000000000000000000000'
    ciphertext = '00000000000000000000000000000000'

    paddingLength = 1
    while paddingLength <= 16:
        garbage = bruteforceByte(garbage, block, 16 - paddingLength)
        paddingLength = checkPaddingLength(garbage, block, paddingLength)
        garbage, ciphertext = nextIteration(garbage,ciphertext, paddingLength)
        
        paddingLength = paddingLength + 1

    return ciphertext

if __name__ == "__main__":
    #s = sys.argv[1]
    #blocks = [s[i:i + 2 * 16] for i in range(0, len(s), 2 * 16)]

    string = 'c3eaefed61bf18720dbe1ef46cb1d89353f8518024986a2a1fbc33df4e16ecc0'
    ciphertext = binascii.hexlify(cbc.encryptbinary(binascii.unhexlify(string), cbc.iv))
    blocks = [ciphertext[i:i + 2 * 16] for i in range(0, len(ciphertext), 2 * 16)]
    print blocks

    for i in range(len(blocks)):
        if (i == 0):
            lastcipher = binascii.hexlify(cbc.iv)
        else:
            lastcipher = blocks[i - 1]

        print 'plaintext: ' + string[32 * i:32 * (i + 1)]
        print xorBlock(attack(blocks[i]), lastcipher)
   
