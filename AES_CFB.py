from AES import key_expansion, Cipher
from AESHelp import xor, pad_strip, msb, lsb, aes_file_helper


def aes_encrypt_cfb(key, bits, s, in_name, out_name='file'):
    """
aes_encrypt_cfb(key, bits, s, in_name, out_name='file') -> file

aes_encrypt_cfb performs 128, 192, or 256-bit AES encryption
using the s-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    from os import urandom
    b, f_in, f_out, keys, n_k = aes_cfb_helper(bits, in_name, key, out_name, s)
    iv = urandom(16)
    f_out.write(iv)
    piece = f_in.read(b)
    while piece != b'':
        p_len = len(piece)
        if p_len < b:
            piece = piece + b'\x80' + bytes(b - p_len - 1)
        output = Cipher(iv, keys, n_k)
        encrypted_output = xor(piece, msb(s, output))
        f_out.write(encrypted_output)
        piece = f_in.read(b)
        iv = lsb(128 - s, iv) + encrypted_output
    f_in.close()
    f_out.close()


def aes_cfb_helper(bits, in_name, key, out_name, s):
    f_in, f_out, n_k = aes_file_helper(bits, in_name, out_name)
    if s % 8 != 0 or s < 8 or s > 128:
        raise Exception("s must be a multiple of 8, between 8 and 128")
    b = s // 8
    keys = key_expansion(key, n_k)
    return b, f_in, f_out, keys, n_k


def aes_decrypt_cfb(key, bits, s, in_name, out_name):
    """
aes_decrypt_cfb(key, bits, s, in_name, out_name) -> file

aes_decrypt_cfb performs 128, 192, or 256-bit AES decryption
using the s-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """

    byte, f_in, f_out, keys, n_k = aes_cfb_helper(bits, in_name, key, out_name, s)
    data_in = f_in.read(16)
    data_out = f_in.read(byte)
    while data_out != b'':
        o = Cipher(data_in, keys, n_k)
        p = xor(data_out, msb(s, o))
        data_in = lsb(128 - s, data_in) + data_out
        data_out = f_in.read(byte)
        if data_out == b'' and byte > 1:
            p = pad_strip(p)
        f_out.write(p)
    f_in.close()
    f_out.close()


def aes_encrypt_128_cfb_8(key, in_name, out_name='file'):
    """
aes_encrypt_128_cfb_8(key, in_name, out_name='file') -> file
  
aes_encrypt_128_cfb_8 performs 128-bit AES encryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_encrypt_cfb(key, 128, 8, in_name, out_name)


def aes_encrypt_192_cfb_8(key, in_name, out_name='file'):
    """
aes_encrypt_192_cfb_8(key, in_name, out_name='file') -> file
  
aes_encrypt_192_cfb_8 performs 192-bit AES encryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_encrypt_cfb(key, 192, 8, in_name, out_name)


def aes_encrypt_256_cfb_8(key, in_name, out_name='file'):
    """
aes_encrypt_256_cfb_8(key, in_name, out_name='file') -> file
  
aes_encrypt_256_cfb_8 performs 256-bit AES encryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_encrypt_cfb(key, 256, 8, in_name, out_name)


def aes_decrypt_128_cfb_8(key, in_name, out_name='file'):
    """
aes_decrypt_128_cfb_8(key, in_name, out_name='file') -> file
  
aes_decrypt_128_cfb_8 performs 128-bit AES decryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_decrypt_cfb(key, 128, 8, in_name, out_name)


def aes_decrypt_192_cfb_8(key, in_name, out_name='file'):
    """
aes_decrypt_192_cfb_8(key, in_name, out_name) -> file

aes_decrypt_192_cfb_8 performs 192-bit AES decryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_decrypt_cfb(key, 192, 8, in_name, out_name)


def aes_decrypt_256_cfb_8(key, in_name, out_name='file'):
    """
aes_decrypt_256_cfb_8(key, in_name, out_name='file') -> file

aes_decrypt_256_cfb_8 performs 256-bit AES decryption using
the 8-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_decrypt_cfb(key, 256, 8, in_name, out_name)


def aes_encrypt_128_cfb_64(key, in_name, out_name='file'):
    """
aes_encrypt_128_cfb_64(key, in_name, out_name='file') -> file
  
aes_encrypt_128_cfb_64 performs 128-bit AES encryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_encrypt_cfb(key, 128, 64, in_name, out_name)


def aes_encrypt_192_cfb_64(key, in_name, out_name='file'):
    """
aes_encrypt_192_cfb_64(key, in_name, out_name='file') -> file

aes_encrypt_192_cfb_64 performs 192-bit AES encryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_encrypt_cfb(key, 192, 64, in_name, out_name)


def aes_encrypt_256_cfb_64(key, in_name, out_name='file'):
    """
aes_encrypt_256_cfb_64(key, in_name, out_name='file') -> file
  
aes_encrypt_256_cfb_64 performs 256-bit AES encryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_encrypt_cfb(key, 256, 64, in_name, out_name)


def aes_decrypt_128_cfb_64(key, in_name, out_name):
    """
aes_decrypt_128_cfb_64(key, in_name, out_name) -> file

aes_decrypt_128_cfb_64 performs 128-bit AES decryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_decrypt_cfb(key, 128, 64, in_name, out_name)


def aes_decrypt_192_cfb_64(key, in_name, out_name):
    """
aes_decrypt_192_cfb_64(key, in_name, out_name) -> file
  
aes_decrypt_192_cfb_64 performs 192-bit AES decryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_decrypt_cfb(key, 192, 64, in_name, out_name)


def aes_decrypt_256_cfb_64(key, in_name, out_name):
    """
aes_decrypt_256_cfb_64(key, in_name, out_name) -> file
  
aes_decrypt_256_cfb_64 performs 256-bit AES decryption using
the 64-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_decrypt_cfb(key, 256, 64, in_name, out_name)


def aes_encrypt_128_cfb_128(key, in_name, out_name='file'):
    """
aes_encrypt_128_cfb_128(key, in_name, out_name='file') -> file
  
aes_encrypt_128_cfb_128 performs 128-bit AES encryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_encrypt_cfb(key, 128, 128, in_name, out_name)


def aes_encrypt_192_cfb_128(key, in_name, out_name='file'):
    """
aes_encrypt_192_cfb_128(key, in_name, out_name='file') -> file
  
aes_encrypt_192_cfb_128 performs 192-bit AES encryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_encrypt_cfb(key, 192, 128, in_name, out_name)


def aes_encrypt_256_cfb_128(key, in_name, out_name='file'):
    """
aes_encrypt_256_cfb_128(key, in_name, out_name='file') -> file
  
aes_encrypt_256_cfb_128 performs 256-bit AES encryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_encrypt_cfb(key, 256, 128, in_name, out_name)


def aes_decrypt_128_cfb_128(key, in_name, out_name):
    """
aes_decrypt_128_cfb_128(key, in_name, out_name) -> file
  
aes_decrypt_128_cfb_128 performs 128-bit AES decryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_decrypt_cfb(key, 128, 128, in_name, out_name)


def aes_decrypt_192_cfb_128(key, in_name, out_name):
    """
aes_decrypt_192_cfb_128(key, in_name, out_name) -> file
  
aes_decrypt_192_cfb_128 performs 192-bit AES decryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_decrypt_cfb(key, 192, 128, in_name, out_name)


def aes_decrypt_256_cfb_128(key, in_name, out_name):
    """
aes_decrypt_256_cfb_128(key, in_name, out_name) -> file
  
aes_decrypt_256_cfb_128 performs 256-bit AES decryption using
the 128-bit Cipher Feedback block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_decrypt_cfb(key, 256, 128, in_name, out_name)
