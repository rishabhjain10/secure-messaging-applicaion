import socket               # Import socket module
import socket, select, string, sys, os, random
import codecs

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(sys.argv[2])
hash_of_message = digest.finalize()
hexlify = codecs.getencoder('hex')
hex_of_hash = hexlify(hash_of_message)[0]
f = open('passwd.txt', 'a')
line =  sys.argv[1] + "***" + hex_of_hash

f.write(line + "\n")




