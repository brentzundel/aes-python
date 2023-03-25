from AES import key_expansion, Cipher
from AESHelp import xor, pad_strip, msb, lsb

def AES_Cipher_OFB(key, bits, mode, inName, outName='myfile'):
  '''
AES_Cipher_OFB(key, bits, mode, inName, outName='myfile') -> file
  
AES_Cipher_OFB performs 128, 192, or 256-bit AES encryption
or decryption using the Output Feedback block cipher mode
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
    raise Exception("%d-bit Encryption is not supported" %(bits))
  keys = key_expansion(key, Nk)
  if mode == 'e':
    I = urandom(16)
    fout.write(I)
  elif mode == 'd':
    I = fin.read(16)
  else:
    raise Exception('Unsupported Mode')
  M = fin.read(16)
  while len(M) == 16:
    I = Cipher(I, keys, Nk)
    fout.write(xor(M, I))
    M = fin.read(16)
  if M != b'':
    I = Cipher(I, keys, Nk)
    fout.write(xor(M, msb(len(M) * 8, I)))
  fin.close()
  fout.close()


 
def AES_Encrypt_128_OFB(key, inName, outName='myfile'):
  '''
AES_Encrypt_128_OFB(key, inName, outName='myfile') -> file
  
AES_Encrypt_128_OFB performs 128-bit AES encryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Cipher_OFB(key, 128, 'e', inName, outName)


def AES_Encrypt_192_OFB(key, inName, outName='myfile'):
  '''
AES_Encrypt_192_OFB(key, inName, outName='myfile') -> file
  
AES_Encrypt_192_OFB performs 192-bit AES encryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Cipher_OFB(key, 192, 'e', inName, outName)


def AES_Encrypt_256_OFB(key, inName, outName='myfile'):
  '''
AES_Encrypt_256_OFB(key, inName, outName='myfile') -> file
  
AES_Encrypt_256_OFB performs 256-bit AES encryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.'''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Cipher_OFB(key, 256, 'e', inName, outName)

  
 
def AES_Decrypt_128_OFB(key, inName, outName):
  '''
AES_Decrypt_128_OFB(key, inName, outName) -> file
  
AES_Decrypt_128_OFB performs 128-bit AES decryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 16:
    raise Exception('key must be 128 bits long')
  AES_Cipher_OFB(key, 128, 'd', inName, outName)


def AES_Decrypt_192_OFB(key, inName, outName):
  '''
AES_Decrypt_192_OFB(key, inName, outName) -> file
  
AES_Decrypt_192_OFB performs 192-bit AES decryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 24:
    raise Exception('key must be 192 bits long')
  AES_Cipher_OFB(key, 192, 'd', inName, outName)


def AES_Decrypt_256_OFB(key, inName, outName):
  '''
AES_Decrypt_256_OFB(key, inName, outName) -> file
  
AES_Decrypt_256_OFB performs 256-bit AES decryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  '''
  if len(hex(key)[2:])/2 != 32:
    raise Exception('key must be 256 bits long')
  AES_Cipher_OFB(key, 256, 'd', inName, outName)
