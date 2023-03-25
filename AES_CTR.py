from AES import KeyExpansion, Cipher
from AESHelp import xor, padStrip, MSB, LSB

def AES_Cipher_CTR(key, bits, mode, inName, outName='myfile'):
  '''
AES_Cipher_CTR(key, bits, mode, inName, outName='myfile') -> file
  
AES_Cipher_CTR performs 128, 192, or 256-bit AES encryption
or decryption using the Counter block cipher mode
of operation described in NIST Special Publication 800-38A.'''
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
    raise Exception("%d-bit Encryption is  not supported" %(bits))
  keys = KeyExpansion(key, Nk)
  if mode == 'e':
    ctr = urandom(16)
    fout.write(ctr)
  elif mode == 'd':
    ctr = fin.read(16)
  else:
    raise Exception('Unsupported Mode')
  M = fin.read(16)
  while len(M) == 16:
    I = Cipher(ctr, keys, Nk)
    fout.write(xor(M, I))
    M = fin.read(16)
    ctr = increment(ctr)
  if M != b'':
    I = Cipher(ctr, keys, Nk)
    fout.write(xor(M, MSB(len(M)*8, I)))
  fin.close()
  fout.close()


 
def increment(OS, i=1):
  '''
increment(OS, i=1) -> bytes

increment takes a bytes object and returns a 
bytes object that has been incremented by i.'''
  if OS == b'':
    return b''
  else:
    x = OS[-1]
    x += i
    if x > 255:
      return increment(OS[0:-1]) + b'\x00'
    else:
      return OS[0:-1] + bytes([x])
  

def AES_Encrypt_128_CTR(key, inName, outName='myfile'):
  '''
AES_Encrypt_128_CTR(key, inName, outName='myfile') -> file

AES_Encrypt_128_CTR performs 128-bit AES encryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Cipher_CTR(key, 128, 'e', inName, outName)


def AES_Encrypt_192_CTR(key, inName, outName='myfile'):
  '''
AES_Encrypt_192_CTR(key, inName, outName='myfile') -> file

AES_Encrypt_192_CTR performs 192-bit AES encryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Cipher_CTR(key, 192, 'e', inName, outName)


def AES_Encrypt_256_CTR(key, inName, outName='myfile'):
  '''
AES_Encrypt_256_CTR(key, inName, outName='myfile') -> file

AES_Encrypt_256_CTR performs 256-bit AES encryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Cipher_CTR(key, 256, 'e', inName, outName)

  
 
def AES_Decrypt_128_CTR(key, inName, outName):
  '''
AES_Decrypt_128_CTR(key, inName, outName) -> file
  
AES_Decrypt_128_CTR performs 128-bit AES decryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Cipher_CTR(key, 128, 'd', inName, outName)


def AES_Decrypt_192_CTR(key, inName, outName):
  '''
AES_Decrypt_192_CTR(key, inName, outName) -> file
  
AES_Decrypt_192_CTR performs 192-bit AES decryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Cipher_CTR(key, 192, 'd', inName, outName)


def AES_Decrypt_256_CTR(key, inName, outName):
  '''
AES_Decrypt_256_CTR(key, inName, outName) -> file
  
AES_Decrypt_256_CTR performs 256-bit AES decryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Cipher_CTR(key, 256, 'd', inName, outName)
