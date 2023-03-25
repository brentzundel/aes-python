from AES import Cipher, InvCipher, key_expansion
from AESHelp import pad_strip, aes_file_helper


def aes_encrypt_ecb(key, bits, in_name, out_name='file'):
    """
aes_encrypt_ecb(key, bits, in_name, out_name='file') -> file
  
aes_encrypt_ecb performs 128, 192, or 256-bit AES encryption
using the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A."""
    f_in, f_out, n_k = aes_file_helper(bits, in_name, out_name)
    keys = key_expansion(key, n_k)
    os = f_in.read(16)
    while os != b'':
        m_len = len(os)
        if m_len < 16:
            m = os + b'\x80' + bytes(16 - m_len - 1)
        else:
            m = os
        c = Cipher(m, keys, n_k)
        f_out.write(c)
        os = f_in.read(16)
    f_in.close()
    f_out.close()


def aes_decrypt_ecb(key, bits, in_name, out_name):
    """
aes_decrypt_ecb(key, bits, in_name, out_name) -> file
  
aes_decrypt_ecb performs 128, 192, or 256-bit AES decryption
using the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    f_in, f_out, n_k = aes_file_helper(bits, in_name, out_name)
    keys = key_expansion(key, n_k)
    os = f_in.read(16)
    while os != b'':
        c = os
        os = f_in.read(16)
        m = InvCipher(c, keys, n_k)
        if os == b'':
            m = pad_strip(m)
        f_out.write(m)
    f_in.close()
    f_out.close()


def aes_encrypt_128_ecb(key, in_name, out_name='file'):
    """
aes_encrypt_128_ecb(key, in_name, out_name='file') -> file
  
aes_encrypt_128_ecb performs 128-bit AES encryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_encrypt_ecb(key, 128, in_name, out_name)


def aes_encrypt_192_ecb(key, in_name, out_name='file'):
    """
aes_encrypt_192_ecb(key, in_name, out_name='file') -> file
  
aes_encrypt_192_ecb performs 192-bit AES encryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_encrypt_ecb(key, 192, in_name, out_name)


def aes_encrypt_256_ecb(key, in_name, out_name='file'):
    """
aes_encrypt_256_ecb(key, in_name, out_name='file') -> file
  
aes_encrypt_256_ecb performs 256-bit AES encryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_encrypt_ecb(key, 256, in_name, out_name)


def aes_decrypt_128_ecb(key, in_name, out_name):
    """
aes_decrypt_128_ecb(key, in_name, out_name) -> file
  
aes_decrypt_128_ecb performs 128-bit AES decryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_decrypt_ecb(key, 128, in_name, out_name)


def aes_decrypt_192_ecb(key, in_name, out_name):
    """
aes_decrypt_192_ecb(key, in_name, out_name) -> file
  
aes_decrypt_192_ecb performs 192-bit AES decryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_decrypt_ecb(key, 192, in_name, out_name)


def aes_decrypt_256_ecb(key, in_name, out_name):
    """
aes_decrypt_256_ecb(key, in_name, out_name) -> file
  
aes_decrypt_256_ecb performs 256-bit AES decryption using
the Electronic Code Book block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_decrypt_ecb(key, 256, in_name, out_name)
