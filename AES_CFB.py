from AES import KeyExpansion, Cipher
from AESHelp import xor, padStrip, MSB, LSB

def AES_Encrypt_CFB(key, bits, s, inName, outName='myfile'):
  '''
AES_Encrypt_CFB(key, bits, s, inName, outName='myfile') -> file

AES_Encrypt_CFB performs 128, 192, or 256-bit AES encryption
using the s-bit Cipher Feedback block cipher mode of operation
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
  if s % 8 != 0 or s < 8 or s > 128:
    raise Exception("s must be a multiple of 8, between 8 and 128")
  B = s//8
  keys = KeyExpansion(key, Nk)
  IV = urandom(16)
  fout.write(IV)
  I = IV
  P = fin.read(B)
  while P != b'':
    pLen = len(P)
    if pLen < B:
      P = P + b'\x80' + bytes(B - pLen - 1)
    O = Cipher(I, keys, Nk)
    C = xor(P, MSB(s, O))
    fout.write(C)
    P = fin.read(B)
    I = LSB(128-s, I) + C
  fin.close()
  fout.close()

 
def AES_Decrypt_CFB(key, bits, s, inName, outName):
  '''
AES_Decrypt_CFB(key, bits, s, inName, outName) -> file
  
AES_Decrypt_CFB performs 128, 192, or 256-bit AES decryption
using the s-bit Cipher Feedback block cipher mode of operation
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
  if s % 8 != 0 or s < 8 or s > 128:
    raise Exception("s must be a multiple of 8, between 8 and 128")
  B = s//8
  keys = KeyExpansion(key, Nk)
  I = fin.read(16)
  C = fin.read(B)
  while C != b'':
    O = Cipher(I, keys, Nk)
    P = xor(C, MSB(s, O))
    I = LSB(128-s, I) + C
    C = fin.read(B)
    if C == b'' and B > 1:
      P = padStrip(P)
    fout.write(P)
  fin.close()
  fout.close()


 
def AES_Encrypt_128_CFB_8(key, inName, outName='myfile'):
  '''
AES_Encrypt_128_CFB_8(key, inName, outName='myfile') -> file
  
AES_Encrypt_128_CFB_8 performs 128-bit AES encryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Encrypt_CFB(key, 128, 8, inName, outName)


def AES_Encrypt_192_CFB_8(key, inName, outName='myfile'):
  '''
AES_Encrypt_192_CFB_8(key, inName, outName='myfile') -> file
  
AES_Encrypt_192_CFB_8 performs 192-bit AES encryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Encrypt_CFB(key, 192, 8, inName, outName)


def AES_Encrypt_256_CFB_8(key, inName, outName='myfile'):
  '''
AES_Encrypt_256_CFB_8(key, inName, outName='myfile') -> file
  
AES_Encrypt_256_CFB_8 performs 256-bit AES encryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Encrypt_CFB(key, 256, 8, inName, outName)

  
 
def AES_Decrypt_128_CFB_8(key, inName, outName):
  '''
AES_Decrypt_128_CFB_8(key, inName, outName) -> file
  
AES_Decrypt_128_CFB_8 performs 128-bit AES decryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Decrypt_CFB(key, 128, 8, inName, outName)


def AES_Decrypt_192_CFB_8(key, inName, outName):
  '''
AES_Decrypt_192_CFB_8(key, inName, outName) -> file

AES_Decrypt_192_CFB_8 performs 192-bit AES decryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Decrypt_CFB(key, 192, 8, inName, outName)


def AES_Decrypt_256_CFB_8(key, inName, outName):
  '''
AES_Decrypt_256_CFB_8(key, inName, outName) -> file

AES_Decrypt_256_CFB_8 performs 256-bit AES decryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Decrypt_CFB(key, 256, 8, inName, outName)

 
def AES_Encrypt_128_CFB_64(key, inName, outName='myfile'):
  '''
AES_Encrypt_128_CFB_64(key, inName, outName='myfile') -> file
  
AES_Encrypt_128_CFB_64 performs 128-bit AES encryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Encrypt_CFB(key, 128, 64, inName, outName)


def AES_Encrypt_192_CFB_64(key, inName, outName='myfile'):
  '''
AES_Encrypt_192_CFB_64(key, inName, outName='myfile') -> file

AES_Encrypt_192_CFB_64 performs 192-bit AES encryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Encrypt_CFB(key, 192, 64, inName, outName)


def AES_Encrypt_256_CFB_64(key, inName, outName='myfile'):
  '''
AES_Encrypt_256_CFB_64(key, inName, outName='myfile') -> file
  
AES_Encrypt_256_CFB_64 performs 256-bit AES encryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Encrypt_CFB(key, 256, 64, inName, outName)

  
 
def AES_Decrypt_128_CFB_64(key, inName, outName):
  '''
AES_Decrypt_128_CFB_64(key, inName, outName) -> file

AES_Decrypt_128_CFB_64 performs 128-bit AES decryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Decrypt_CFB(key, 128, 64, inName, outName)


def AES_Decrypt_192_CFB_64(key, inName, outName):
  '''
AES_Decrypt_192_CFB_64(key, inName, outName) -> file
  
AES_Decrypt_192_CFB_64 performs 192-bit AES decryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Decrypt_CFB(key, 192, 64, inName, outName)


def AES_Decrypt_256_CFB_64(key, inName, outName):
  '''
AES_Decrypt_256_CFB_64(key, inName, outName) -> file
  
AES_Decrypt_256_CFB_64 performs 256-bit AES decryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Decrypt_CFB(key, 256, 64, inName, outName)

 
def AES_Encrypt_128_CFB_128(key, inName, outName='myfile'):
  '''
AES_Encrypt_128_CFB_128(key, inName, outName='myfile') -> file
  
AES_Encrypt_128_CFB_128 performs 128-bit AES encryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Encrypt_CFB(key, 128, 128, inName, outName)


def AES_Encrypt_192_CFB_128(key, inName, outName='myfile'):
  '''
AES_Encrypt_192_CFB_128(key, inName, outName='myfile') -> file
  
AES_Encrypt_192_CFB_128 performs 192-bit AES encryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Encrypt_CFB(key, 192, 128, inName, outName)


def AES_Encrypt_256_CFB_128(key, inName, outName='myfile'):
  '''
AES_Encrypt_256_CFB_128(key, inName, outName='myfile') -> file
  
AES_Encrypt_256_CFB_128 performs 256-bit AES encryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Encrypt_CFB(key, 256, 128, inName, outName)

  
 
def AES_Decrypt_128_CFB_128(key, inName, outName):
  '''
AES_Decrypt_128_CFB_128(key, inName, outName) -> file
  
AES_Decrypt_128_CFB_128 performs 128-bit AES decryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Decrypt_CFB(key, 128, 128, inName, outName)


def AES_Decrypt_192_CFB_128(key, inName, outName):
  '''
AES_Decrypt_192_CFB_128(key, inName, outName) -> file
  
AES_Decrypt_192_CFB_128 performs 192-bit AES decryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Decrypt_CFB(key, 192, 128, inName, outName)


def AES_Decrypt_256_CFB_128(key, inName, outName):
  '''
AES_Decrypt_256_CFB_128(key, inName, outName) -> file
  
AES_Decrypt_256_CFB_128 performs 256-bit AES decryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Decrypt_CFB(key, 256, 128, inName, outName)
