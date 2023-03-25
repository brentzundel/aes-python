from AES import KeyExpansion, Cipher, InvCipher
from AESHelp import padStrip, xor


def AES_Encrypt_CBC(key, bits, inName, outName='myfile'):
  '''
AES_Encrypt_CBC(key, bits, inName, outName='myfile') -> file
  
AES_Encrypt_CBC performs 128, 192, or 256-bit AES encryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.'''
  from os import urandom
  try:
    fin = open(inName, 'rb')
  except:
    raise Exception("Error opening file: %s" %(inName))
  try:
    fout = open(outName, 'wb')
  except:
    raise Exception("Error opening output file")
  if bits == 128:
    Nk = 4
  elif bits == 192:
    Nk = 6
  elif bits == 256:
    Nk = 8
  else:
    raise Exception("%d-bit Encryption is not supported" %(bits))
  keys = KeyExpansion(key, Nk)
  IV = urandom(16)
  fout.write(IV)
  C = IV
  OS = fin.read(16)
  while OS != b'':
    mLen = len(OS)
    if mLen < 16:
      PT = OS + b'\x80' + bytes(16 - mLen - 1)
    else:
      PT = OS
    C = Cipher(xor(PT, C), keys, Nk)
    fout.write(C)
    OS = fin.read(16)
  fin.close()
  fout.close()

 
def AES_Decrypt_CBC(key, bits, inName, outName):
  '''
AES_Decrypt_CBC(key, bits, inName, outName) -> file
  
AES_Decrypt_CBC performs 128, 192, or 256-bit AES decryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.  '''
  try:
    fin = open(inName, 'rb')
  except:
    raise Exception("Error opening file: %s" %(inName))
  try:
    fout = open(outName, 'wb')
  except:
    raise Exception("Error opening output file")
  if bits == 128:
    Nk = 4
  elif bits == 192:
    Nk = 6
  elif bits == 256:
    Nk = 8
  else:
    raise Exception("%d-bit Encryption is not supported" %(bits))
  keys = KeyExpansion(key, Nk)
  IV = fin.read(16)
  OS = fin.read(16)
  while OS != b'':
    M = xor(InvCipher(OS, keys, Nk), IV)
    IV = OS
    OS = fin.read(16)
    if OS == b'':
      M = padStrip(M)
    fout.write(M)
  fin.close()
  fout.close()


 
def AES_Encrypt_128_CBC(key, inName, outName='myfile'):
  '''
AES_Encrypt_128_CBC(key, inName, outName='myfile') -> file
  
AES_Encrypt_128_CBC performs 128-bit AES encryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Encrypt_CBC(key, 128, inName, outName)


def AES_Encrypt_192_CBC(key, inName, outName='myfile'):
  '''
AES_Encrypt_192_CBC(key, inName, outName='myfile') -> file
  
AES_Encrypt_192_CBC performs 192-bit AES encryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Encrypt_CBC(key, 192, inName, outName)


def AES_Encrypt_256_CBC(key, inName, outName='myfile'):
  '''
AES_Encrypt_256_CBC(key, inName, outName='myfile') -> file
  
AES_Encrypt_256_CBC performs 256-bit AES encryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Encrypt_CBC(key, 256, inName, outName)

  
 
def AES_Decrypt_128_CBC(key, inName, outName):
  '''
AES_Decrypt_128_CBC(key, inName, outName) -> file
  
AES_Decrypt_128_CBC performs 128-bit AES decryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Decrypt_CBC(key, 128, inName, outName)


def AES_Decrypt_192_CBC(key, inName, outName):
  '''
AES_Decrypt_192_CBC(key, inName, outName) -> file
  
AES_Decrypt_192_CBC performs 192-bit AES decryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Decrypt_CBC(key, 192, inName, outName)


def AES_Decrypt_256_CBC(key, inName, outName):
  '''
AES_Decrypt_256_CBC(key, inName, outName) -> file
  
AES_Decrypt_256_CBC performs 256-bit AES decryption
using the Cipher Block Chaining mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Decrypt_CBC(key, 256, inName, outName)
