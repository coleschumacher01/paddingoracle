import binascii
import cbc
import paddingoracle
import sys


#incerement an individual hex digit
def hexincrement(c):

    currentspot = ''

    if c.isdigit() and int(c) < 9:
        currentspot = str(int(c) + 1)
    elif c.isdigit():
        currentspot = 'a'
    elif currentspot == 'a':
        currentspot = 'b'
    elif currentspot == 'b':
        currentspot = 'c'
    elif currentspot == 'c':
        currentspot = 'd'
    elif currentspot == 'd':
        currentspot = 'e'
    elif currentspot == 'e':
        currentspot = 'f'
    else:
        currentspot = '0'

    return currentspot

#checks who many bytes are correctly padded
def incrementNextPad(s, current):
    currentspot = s[len(s) - 2*(current + 1): len(s) - current*2]
    newval = hexincrement(currentspot[1])
    currentspot = currentspot[0] + newval
    if newval == '0':
        currentspot = hexincrement(currentspot[0]) + newval
    print(currentspot)
    return s[:len(s) - 2*(current + 1)] + currentspot + s[len(s) - current*2:]

#checks to see how much of the block is corectly padded
def checkIncrements(s, lastcipher, current):
    valid = False

    #if incrementing a padding byte makes the padding invalid then it
    #must already be correct and can be skiped
    while not valid:
        temp = lastcipher
        current += 1
        temp = incrementNextPad(temp, current)
        print(temp)
        valid = paddingoracle.checkPadding(s, temp)
        print(current, valid)
    return current

def getBlockValue(lastcipher, currentcipher):
    currentpadding = 0
    fullstring = binascii.hexlify(lastcipher+currentcipher)
    currentcipher = binascii.hexlify(currentcipher)
    lastciper = binascii.hexlify(lastcipher)
    print(fullstring)
    while currentpadding < 16:
        if paddingoracle.checkPadding(currentcipher, lastcipher):
            currentpadding = checkIncrements(currentcipher, lastcipher, currentpadding)
        else:
            lastcipher = incrementNextPad(lastcipher, currentpadding)

#begin by breaking to code into the initial blocks

s = binascii.unhexlify(sys.argv[1])

lastcipher = cbc.iv
currentcipher = s[:16]
getBlockValue(lastcipher, currentcipher)

