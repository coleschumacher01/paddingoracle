# paddingoracle
Authors: CSole Schumacher, Alex Morgan
This project coinsists of four major components; ecb.py, cbc.py, paddingoracle.py and paddedoracleattack.py.
ecb.py and cbc.py work as directed and offer four different options -e, -d, -u and -s.
The commands can be run with python2 by using the commands python ecb.py <op> <stringtoworkwith>
The padding oracle and padded oracle attack only need to be run with python paddingoracle.py <ciphertoworkwith>.
The padding oracle returns true or false depending on if the padding in the last block of the cipher is correct.
The padding oracle attack will take the input string and output its plaintext without calling the decrypt methods
from either cbc or ecb. All objectives including the extra credit were achieved. encrypt the given string with
cbc.py and option -s and then give that string to the padding oracle attack file.
