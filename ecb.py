from Crypto.Cipher import AES
import binascii
import sys

BLOCK_SIZE = 16
key = binascii.unhexlify('00112233445566778899aabbccddeeff')

#adds padding before encrypting
def pad(s):
    #print(binascii.hexlify(s[:8]))
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    return s + pad_len * chr(pad_len).encode('ascii')

#removes padding after decrytion
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

#encrypts the raw data given with the key after padding it
def encrypt(key, raw):
    raw = pad(raw)
    #print(binascii.hexlify(raw))
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(raw)

#decrypts the data given with the key and unpads it if told , the unpad var is added to simplify
#the oracle program and decryption of individual blocks
def decrypt(key, enc, tounpad = True):
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(enc)
    toreturn = dec
    if tounpad:
        toreturn = unpad(dec)
    return toreturn

#gets the arguments given to the program and maps them
def getopts(argv):
    opts = {}
    while argv:
        if argv[0][0] == '-':
            opts[argv[0]] = argv[1]
        argv = argv[1:]
    return opts

#the main command the executes all functions of the program
if __name__ == "__main__":
    myargs = getopts(sys.argv)

    if '-e' in myargs:
        plaintext = binascii.unhexlify(myargs['-e'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext: ' + binascii.hexlify(ciphertext))
    elif '-d' in myargs:
        ciphertext = binascii.unhexlify(myargs['-d'])
        plaintext = decrypt(key, ciphertext, True)
        print('Plaintext: ' + binascii.hexlify(plaintext))
    elif '-s' in myargs:
        plaintext = binascii.a2b_qp(myargs['-s'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext: ' + binascii.hexlify(ciphertext))
    elif '-u' in myargs:
        ciphertext = binascii.unhexlify(myargs['-u'])
        plaintext = decrypt(key, ciphertext, True)
        print('Plaintext: ' + binascii.b2a_qp(plaintext))
    else:
        print("python ecb.py -e 010203040506")
        print("python ecb.py -s 'this is cool'")
        print("python ecb.py -d d25a16fe349cded7f6a2f2446f6da1c2")
        print("python ecb.py -u 9b43953eeb6c3b7b7971a8bec1a90819")
    