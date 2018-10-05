'''
This file implements the adding oracle using methods from the cbc.py file.
It checks if a string given to it is valid and wether the padding apended to
it is valid as well.
Author: Cole Schumacher
'''

import cbc
import binascii
import sys


def checkPadding(s, iv):
    length = 3
    valid = True
    padding = ''

    #get the full unencrypted text with padding while checking for validity
    try:
        s = binascii.unhexlify(s)
        plaintext = cbc.decryptbinary(s, iv, False)
        padding = binascii.hexlify(
            plaintext[-ord(plaintext[len(plaintext) - 1:]):])
        length = len(padding)
    except ValueError:
        valid = False
    except TypeError:
        valid = False

    #know that the number of padding values will equal
    #the last value so only need to check them for equality
    initial = padding[length - 2: length]
    for i in range(3, length, 2):

        #acount for out of bounds exceptions with AFNP styling
        try:
            current = padding[length - i - 1:length - i + 1]
            valid = valid and initial == current
        except IndexError:
            valid = False

    return valid


if __name__ == "__main__":
    print(checkPadding(sys.argv[1], cbc.iv))
