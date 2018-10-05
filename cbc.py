'''
This file impements cbc encryption using function from the ecb.py file.
It breaks up a string into blocks and either encrypts or decrypts it.
Author Cole Schumacher
'''

from Crypto.Cipher import XOR
import ecb
import sys
import binascii

iv = binascii.unhexlify('000102030405060708090a0b0c0d0e0f')

#encrypts an individual block by xoring it with the last blocks cipher and then encrypting
def encryptblock(lastcipher, plaintext):
    toXOR = XOR.new(lastcipher)
    if len(plaintext) != 16:
        plaintext = ecb.pad(plaintext)
    block = toXOR.encrypt(plaintext)
    return ecb.encrypt(ecb.key, block, False)

#decrypts the given blok and then xors it with the revious block
def decryptblock(lastcipher, ciphertext, unpad):
    block = ecb.decrypt(ecb.key, ciphertext, unpad)

    toXOR = XOR.new(lastcipher)
    block = toXOR.decrypt(block)
    return block

#gets the range of data in the current block
def getrange(first, last, length):
    return last, last + 16

#encryts the given data block by block
def encryptbinary(s, initializationVector):
    length = len(s)
    currentstart = 0
    currentend = 16

    if currentend > length:
        currentend = length

    ciphertext = binascii.unhexlify('')
    lastcipher = initializationVector
    
    #itterates of the raw data and blocks them
    while currentstart < length:

        plaintext = s[currentstart:currentend]
        print(binascii.hexlify(plaintext))
        currentcipher = encryptblock(lastcipher, plaintext)
            
        lastcipher = currentcipher

        #moves to the next block
        ciphertext += currentcipher
        currentstart, currentend = getrange(currentstart, currentend, length)

    if length % ecb.BLOCK_SIZE == 0:
        padding = ecb.pad(binascii.unhexlify(''))
        ciphertext += encryptblock(lastcipher, padding)

    return ciphertext

#decrypts the data given and unpads it if told
def decryptbinary(s, initializationVector, unpad):
    length = len(s)
    currentstart = 0
    currentend = 16

    if currentend > length:
        currentend = length

    plaintext = binascii.unhexlify('')
    lastcipher = initializationVector
    

    #iterates over the cipher and blocks it
    while currentstart < length:

        ciphertext = s[currentstart:currentend]
        print(binascii.hexlify(ciphertext))


        #decrypt the current block, no reason to have it decrypted in ecb because
        #it would need to be added back in for all nonerminal blocks
        plaintext += decryptblock(lastcipher, ciphertext, False)

        #move to the next block
        lastcipher = ciphertext
        currentstart, currentend = getrange(currentstart, currentend, length)

    #print(len(lastcipher))
    ##if len(lastcipher) == 32:
     #   ciphertext = lastcipher[16:]
     #   lastcipher = lastcipher[:16]
     #   plaintext = plaintext[:len(plaintext) - 16] + decryptblock(lastcipher, ciphertext, False)

    #removes padding from the string as a whole if requested
    if unpad:
        plaintext = ecb.unpad(plaintext)

    return plaintext

#the main function that executes all functions of the program
if __name__ == "__main__":
    myargs = ecb.getopts(sys.argv)

    try:
        if '-e' in myargs:
            plaintext = binascii.unhexlify(myargs['-e'])
            ciphertext = encryptbinary(plaintext, iv)
            print('Ciphertext: ' + binascii.hexlify(ciphertext))

        elif '-d' in myargs:
            ciphertext = binascii.unhexlify(myargs['-d'])
            plaintext = decryptbinary(ciphertext, iv, True)
            print('Plaintext: ' + binascii.hexlify(plaintext))

        elif '-s' in myargs:
            plaintext = binascii.a2b_qp(myargs['-s'])
            ciphertext = encryptbinary(plaintext, iv)
            print('Ciphertext: ' + binascii.hexlify(ciphertext))

        elif '-u' in myargs:
            ciphertext = binascii.unhexlify(myargs['-u'])
            plaintext = decryptbinary(ciphertext, iv, True)
            print('Plaintext: ' + binascii.b2a_qp(plaintext))
    except TypeError:
        print("Invalid input: check to ensure that your string is of the correct length with valid characters")
