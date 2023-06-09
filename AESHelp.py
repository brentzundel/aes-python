from AES import KeyExpansion
from AESTables import ltable, a_table


def in_to_state(bytestring, n_b=4):
    """
in_to_state(bytestring, n_b=4) -> state

in_to_state copies bytestream (bytes) to a state
(list of lists of ints) according to the scheme described
in section 3.4 of the Advanced Encryption Standard (FIPS 197)."""
    state = [[0 for _ in range(4)] for _ in range(n_b)]
    for r in range(4):
        for c in range(n_b):
            state[r][c] = bytestring[r + 4 * c]
    return state


def out_from_state(state, n_b=4):
    """
out_from_state(state, n_b=4) -> out

out_from_state copies state (2D array of longs) to out
(byte string) according to the scheme described
in section 3.4 of the Advanced Encryption Standard (FIPS 197)."""
    long = bytearray()
    for col in range(n_b):
        for row in range(4):
            long.append(state[row][col])
    return long


def pad_strip(os):
    """
pad_strip(os) -> os

pad_strip removes the padding of '\x80\x00...' from
the end of the byte string os."""
    flag = True
    j = 0
    os_len = len(os)
    for i in range(1, os_len):
        if os[-i] == 0:
            flag = True and flag
            j += 1
        else:
            flag = False
            break
        if os[os_len - j - 1] == 128:
            flag = True and flag
            break
    if flag:
        return os[0:os_len - j - 1]
    else:
        return os


# prints a list of longs as a hexadecimal string
def print_list_as_hex_string(longs):
    out = ''
    for x in map(hex, longs):
        if len(x[2:4]) == 1:
            out += '0' + x[2:4]
        else:
            out += x[2:4]
    return out


# prints a 2D array of longs as a 2d hexadecimal block
def print_state(state, length=4):
    for i in range(length):
        print(print_list_as_hex_string(state[i]))


def prints(s):
    """
prints(state) -> None

Prints the state to stdout."""
    x = out_from_state(s)
    for i in x:
        print(hex(i)[2:], end='')
    print()


def xor(byte_string1, byte_string2):
    """
xor(byte_string1, byte_string2) -> bytes

xor performs the exclusive-or operation on two byte strings."""
    length = len(byte_string1)
    if length != len(byte_string2):
        raise Exception("Byte strings are of different lengths")
    z = bytearray()
    for i in range(length):
        z.append(byte_string1[i] ^ byte_string2[i])
    return z


def msb(s, os):
    """
msb(s, os) -> os

msb returns the s most significant bits from os."""
    b = s // 8
    return os[0:b]


def lsb(s, os):
    """
lsb(s, os) -> os

lsb returns the s least-significant bits from os."""
    b = s // 8
    if s == 0:
        return b''
    else:
        return os[-b:]


def aes_file_helper(bits, in_name, out_name):
    try:
        f_in = open(in_name, 'rb')
    except OSError:
        raise
    try:
        f_out = open(out_name, 'wb')
    except OSError:
        raise
    if bits == 128:
        n_k = 4
    elif bits == 192:
        n_k = 6
    elif bits == 256:
        n_k = 8
    else:
        raise Exception("%d-bit Encryption is not supported" % bits)
    return f_in, f_out, n_k


def aes_ctr_ofb_helper(bits, in_name, key, mode, out_name):
    from os import urandom
    f_in, f_out, n_k = aes_file_helper(bits, in_name, out_name)
    keys = KeyExpansion(key, n_k)
    if mode == 'e':
        ctr = urandom(16)
        f_out.write(ctr)
    elif mode == 'd':
        ctr = f_in.read(16)
    else:
        raise Exception('Unsupported Mode')
    m = f_in.read(16)
    return ctr, f_in, f_out, keys, m, n_k


#
# Subordinate Functions for those
# Functions used by AES Cipher
# and AES Inverse Cipher
#
def gf_mult(a, b, n=8, ip=0x11b):
    """
gf_mult(a, b, n=8, ip=0x11b) -> number

gf_mult performs finite field multiplication for Galois
Field 2^n using irreducible polynomial ip. Based on algorithm
found at https://en.wikipedia.org/wiki/Finite_field_arithmetic."""
    p = 0
    test = 2 ** n
    while n > 0:
        if b & 1 == 1:
            p = p ^ a
        else:
            p = p ^ 0
        a = a << 1
        if a & test == test:
            a = a ^ ip
        else:
            a = a ^ 0
        b = b >> 1
        n = n - 1
    return p


def gf_mul(a, b):
    """
gf_mul(a, b) -> number

gf_mul is a Galois Field Multiplication function that is
equivalent to gf_mult, but is based on log and exponent
table lookup to increase security against side channel
attacks.  Based on algorithm found at
https://www.samiam.org/galois.html."""
    z = 0
    s = ltable[a] + ltable[b]
    s %= 255
    s = a_table[s]
    q = s
    if a == 0:
        s = z
    else:
        s = q
    if b == 0:
        s = z
    return s


def get_columns(state, n_b=4):
    """
get_columns(state, n_b=4) -> column list

get_columns converts a state (2D array of longs) into
a column list (2D array of longs).
get_columns is its own inverse, i.e.
  state = get_columns(get_columns(state))."""
    out = [[0 for _ in range(n_b)] for _ in range(4)]
    for col in range(n_b):
        for row in range(4):
            out[col][row] = state[row][col]
    return out
