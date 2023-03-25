from AES import Cipher
from AESHelp import xor, msb, aes_ctr_ofb_helper


def aes_cipher_ctr(key, bits, mode, in_name, out_name='file'):
    """
aes_cipher_ctr(key, bits, mode, in_name, out_name='file') -> file

aes_cipher_ctr performs 128, 192, or 256-bit AES encryption
or decryption using the Counter block cipher mode
of operation described in NIST Special Publication 800-38A."""
    ctr, f_in, f_out, keys, m, n_k = aes_ctr_ofb_helper(bits, in_name, key, mode, out_name)
    while len(m) == 16:
        inp = Cipher(ctr, keys, n_k)
        f_out.write(xor(m, inp))
        m = f_in.read(16)
        ctr = increment(ctr)
    if m != b'':
        inp = Cipher(ctr, keys, n_k)
        f_out.write(xor(m, msb(len(m) * 8, inp)))
    f_in.close()
    f_out.close()


def increment(os, i=1):
    """
increment(os, i=1) -> bytes

increment takes a bytes object and returns a 
bytes object that has been incremented by i."""
    if os == b'':
        return b''
    else:
        x = os[-1]
        x += i
        if x > 255:
            return increment(os[0:-1]) + b'\x00'
        else:
            return os[0:-1] + bytes([x])


def aes_encrypt_128_ctr(key, in_name, out_name='file'):
    """
aes_encrypt_128_ctr(key, in_name, out_name='file') -> file

aes_encrypt_128_ctr performs 128-bit AES encryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_cipher_ctr(key, 128, 'e', in_name, out_name)


def aes_encrypt_192_ctr(key, in_name, out_name='file'):
    """
aes_encrypt_192_ctr(key, in_name, out_name='file') -> file

aes_encrypt_192_ctr performs 192-bit AES encryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_cipher_ctr(key, 192, 'e', in_name, out_name)


def aes_encrypt_256_ctr(key, in_name, out_name='file'):
    """
aes_encrypt_256_ctr(key, in_name, out_name='file') -> file

aes_encrypt_256_ctr performs 256-bit AES encryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A."""
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_cipher_ctr(key, 256, 'e', in_name, out_name)


def aes_decrypt_128_ctr(key, in_name, out_name):
    """
aes_decrypt_128_ctr(key, in_name, out_name) -> file
  
aes_decrypt_128_ctr performs 128-bit AES decryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 16:
        raise Exception('key must be 128 bits long')
    aes_cipher_ctr(key, 128, 'd', in_name, out_name)


def aes_decrypt_192_ctr(key, in_name, out_name):
    """
aes_decrypt_192_ctr(key, in_name, out_name) -> file
  
aes_decrypt_192_ctr performs 192-bit AES decryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 24:
        raise Exception('key must be 192 bits long')
    aes_cipher_ctr(key, 192, 'd', in_name, out_name)


def aes_decrypt_256_ctr(key, in_name, out_name):
    """
aes_decrypt_256_ctr(key, in_name, out_name) -> file
  
aes_decrypt_256_ctr performs 256-bit AES decryption using
the Counter block cipher mode of operation
described in NIST Special Publication 800-38A.  """
    if len(hex(key)[2:]) / 2 != 32:
        raise Exception('key must be 256 bits long')
    aes_cipher_ctr(key, 256, 'd', in_name, out_name)
