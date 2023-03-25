from AES import key_expansion, Cipher, InvCipher
from AESHelp import pad_strip, xor, aes_file_helper


def aes_encrypt_cbc(key, bits, in_name, out_name='file'):
    """
aes_encrypt_cbc(key, bits, in_name, out_name='file') -> file

aes_encrypt_cbc performs 128, 192, or 256-bit AES encryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A."""
    from os import urandom
    f_in, f_out, keys, n_k = aes_cbc_helper(bits, in_name, key, out_name)
    iv = urandom(16)
    f_out.write(iv)
    c = iv
    os = f_in.read(16)
    while os != b'':
        m_len = len(os)
        if m_len < 16:
            pt = os + b'\x80' + bytes(16 - m_len - 1)
        else:
            pt = os
        c = Cipher(xor(pt, c), keys, n_k)
        f_out.write(c)
        os = f_in.read(16)
    f_in.close()
    f_out.close()


def aes_cbc_helper(bits, in_name, key, out_name):
    f_in, f_out, n_k = aes_file_helper(bits, in_name, out_name)
    keys = key_expansion(key, n_k)
    return f_in, f_out, keys, n_k


def aes_decrypt_cbc(key, bits, in_name, out_name):
    """
aes_decrypt_cbc(key, bits, in_name, out_name) -> file

aes_decrypt_cbc performs 128, 192, or 256-bit AES decryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A.  """
    f_in, f_out, keys, n_k = aes_cbc_helper(bits, in_name, key, out_name)
    iv = f_in.read(16)
    os = f_in.read(16)
    while os != b'':
        m = xor(InvCipher(os, keys, n_k), iv)
        iv = os
        os = f_in.read(16)
        if os == b'':
            m = pad_strip(m)
        f_out.write(m)
    f_in.close()
    f_out.close()


def aes_encrypt_128_cbc(key, in_name, out_name='file'):
    """
aes_encrypt_128_cbc(key, in_name, out_name='file') -> file
  
aes_encrypt_128_cbc performs 128-bit AES encryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_encrypt_cbc(key, 128, in_name, out_name)


def aes_encrypt_192_cbc(key, in_name, out_name='file'):
    """
aes_encrypt_192_cbc(key, in_name, out_name='file') -> file
  
aes_encrypt_192_cbc performs 192-bit AES encryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_encrypt_cbc(key, 192, in_name, out_name)


def aes_encrypt_256_cbc(key, in_name, out_name='file'):
    """
aes_encrypt_256_cbc(key, in_name, out_name='file') -> file
  
aes_encrypt_256_cbc performs 256-bit AES encryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_encrypt_cbc(key, 256, in_name, out_name)


def aes_decrypt_128_cbc(key, in_name, out_name):
    """
aes_decrypt_128_cbc(key, in_name, out_name) -> file
  
aes_decrypt_128_cbc performs 128-bit AES decryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_decrypt_cbc(key, 128, in_name, out_name)


def aes_decrypt_192_cbc(key, in_name, out_name):
    """
aes_decrypt_192_cbc(key, in_name, out_name) -> file
  
aes_decrypt_192_cbc performs 192-bit AES decryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_decrypt_cbc(key, 192, in_name, out_name)


def aes_decrypt_256_cbc(key, in_name, out_name):
    """
aes_decrypt_256_cbc(key, in_name, out_name) -> file
  
aes_decrypt_256_cbc performs 256-bit AES decryption
using the cipher Block chaining mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_decrypt_cbc(key, 256, in_name, out_name)
