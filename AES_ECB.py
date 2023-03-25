from AES import Cipher, InvCipher, KeyExpansion
from AESHelp import padStrip, xor


def AES_Encrypt_ECB(key, bits, inName, outName='myfile'):
  '''
AES_Encrypt_ECB(key, bits, inName, outName='myfile') -> file
  
AES_Encrypt_ECB performs 128, 192, or 256-bit AES encryption
using the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.'''
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
  OS = fin.read(16)
  while OS != b'':
    mLen = len(OS)
    if mLen < 16:
      M = OS + b'\x80' + bytes(16 - mLen - 1)
    else:
      M = OS
    c = Cipher(M, keys, Nk)
    fout.write(c)
    OS = fin.read(16)
  fin.close()
  fout.close()


 
def AES_Decrypt_ECB(key, bits, inName, outName):
  '''
AES_Decrypt_ECB(key, bits, inName, outName) -> file
  
AES_Decrypt_ECB performs 128, 192, or 256-bit AES decryption
using the Electronic Code Book block cipher mode of operation
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
  OS = fin.read(16)
  while OS != b'':
    C = OS
    OS = fin.read(16)
    M = InvCipher(C, keys, Nk)
    if OS == b'':
      M = padStrip(M)
    fout.write(M)
  fin.close()
  fout.close()
  

 
def AES_Encrypt_128_ECB(key, inName, outName='myfile'):
  '''
AES_Encrypt_128_ECB(key, inName, outName='myfile') -> file
  
AES_Encrypt_128_ECB performs 128-bit AES encryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Encrypt_ECB(key, 128, inName, outName)


def AES_Encrypt_192_ECB(key, inName, outName='myfile'):
  '''
AES_Encrypt_192_ECB(key, inName, outName='myfile') -> file
  
AES_Encrypt_192_ECB performs 192-bit AES encryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Encrypt_ECB(key, 192, inName, outName)


def AES_Encrypt_256_ECB(key, inName, outName='myfile'):
  '''
AES_Encrypt_256_ECB(key, inName, outName='myfile') -> file
  
AES_Encrypt_256_ECB performs 256-bit AES encryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Encrypt_ECB(key, 256, inName, outName)

  
 
def AES_Decrypt_128_ECB(key, inName, outName):
  '''
AES_Decrypt_128_ECB(key, inName, outName) -> file
  
AES_Decrypt_128_ECB performs 128-bit AES decryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Decrypt_ECB(key, 128, inName, outName)


def AES_Decrypt_192_ECB(key, inName, outName):
  '''
AES_Decrypt_192_ECB(key, inName, outName) -> file
  
AES_Decrypt_192_ECB performs 192-bit AES decryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Decrypt_ECB(key, 192, inName, outName)


def AES_Decrypt_256_ECB(key, inName, outName):
  '''
AES_Decrypt_256_ECB(key, inName, outName) -> file
  
AES_Decrypt_256_ECB performs 256-bit AES decryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Decrypt_ECB(key, 256, inName, outName)
