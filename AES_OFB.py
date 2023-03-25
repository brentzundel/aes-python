from AES import Cipher
from AESHelp import xor, msb, aes_ctr_ofb_helper


def aes_cipher_ofb(key, bits, mode, in_name, out_name='file'):
    """
aes_cipher_ofb(key, bits, mode, in_name, out_name='file') -> file

aes_cipher_ofb performs 128, 192, or 256-bit AES encryption
or decryption using the Output Feedback block cipher mode
of operation described in NIST Special Publication 800-38A."""
    i, f_in, f_out, keys, m, n_k = aes_ctr_ofb_helper(bits, in_name, key, mode, out_name)
    while len(m) == 16:
        i = Cipher(i, keys, n_k)
        f_out.write(xor(m, i))
        m = f_in.read(16)
    if m != b'':
        i = Cipher(i, keys, n_k)
        f_out.write(xor(m, msb(len(m) * 8, i)))
    f_in.close()
    f_out.close()


def aes_encrypt_128_ofb(key, in_name, out_name='file'):
    """
aes_encrypt_128_ofb(key, in_name, out_name='file') -> file
  
aes_encrypt_128_ofb performs 128-bit AES encryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_cipher_ofb(key, 128, 'e', in_name, out_name)


def aes_encrypt_192_ofb(key, in_name, out_name='file'):
    """
aes_encrypt_192_ofb(key, in_name, out_name='file') -> file
  
aes_encrypt_192_ofb performs 192-bit AES encryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_cipher_ofb(key, 192, 'e', in_name, out_name)


def aes_encrypt_256_ofb(key, in_name, out_name='file'):
    """
aes_encrypt_256_ofb(key, in_name, out_name='file') -> file
  
aes_encrypt_256_ofb performs 256-bit AES encryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_cipher_ofb(key, 256, 'e', in_name, out_name)


def aes_decrypt_128_ofb(key, in_name, out_name):
    """
aes_decrypt_128_ofb(key, in_name, out_name) -> file
  
aes_decrypt_128_ofb performs 128-bit AES decryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_cipher_ofb(key, 128, 'd', in_name, out_name)


def aes_decrypt_192_ofb(key, in_name, out_name):
    """
aes_decrypt_192_ofb(key, in_name, out_name) -> file
  
aes_decrypt_192_ofb performs 192-bit AES decryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_cipher_ofb(key, 192, 'd', in_name, out_name)


def aes_decrypt_256_ofb(key, in_name, out_name):
    """
aes_decrypt_256_ofb(key, in_name, out_name) -> file
  
aes_decrypt_256_ofb performs 256-bit AES decryption using
the Output Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_cipher_ofb(key, 256, 'd', in_name, out_name)
