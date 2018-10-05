import binascii
import cbc
import paddingoracle
import sys

def hexincrement(c):

    currrentspot = ''

    if c.isdigit() and int(c) < 9:
        currentspot = str(int(c) + 1)
    elif c.isdigit():
        currentspot = 'a'
    elif currentspot = 'a':
        currentspot = 'b'
    elif currentspot = 'b':
        currentspot = 'c'
    elif currentspot = 'c':
        currentspot = 'd'
    elif currentspot = 'd':
        currentspot = 'e'
    elif currentspot = 'e':
        currentspot = 'f'
    else currentspot = 'f':
        currentspot = '0'
    return currrentspot


def incrementNextPad(s, current):
    currentspot = s[len(s) - 2*(current + 1): len(s) - current*2]
    
    newval = hexincrement(currentspot[1])
    currentspot[1] = newval
    if newval == '0':
        currentspot[0] = hexincrement(currentspot[0])
    return s[:len(s) - 2*(current + 1)] + currentspot + s[len(s) - current*2:]

#checks to see how much of the block is corectly padded
def checkIncrements(s, current):
    valid = False

    #if incrementing a padding byte makes the padding invalid then it
    #must already be correct and can be skiped
    while not valid:
        temp = s
        current += 1
        incrementNextPad(temp, current)
        valid = paddingoracle.checkPadding(temp)
    return current

def getBlockValue(lastcipher, currentcipher):
    currentpadding = 0
    fullstring = binascii.hexlify(lastcipher+currentcipher)
    print(fullstring)
    while currentpadding < 16:
        if paddingoracle.checkPadding(fullstring):
            currentpadding = checkIncrements(fullstring, currentpadding)
        else:
            incrementNextPad(fullstring, currentpadding)

#begin by breaking to code into the initial blocks
try:
    s = binascii.unhexlify(sys.argv[1])

    lastcipher = cbc.iv
    currentcipher = s[16]
    getBlockValue(lastcipher, currentcipher)

except TypeError:
    print("Invalid input string")