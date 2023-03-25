from AESTables import *
from AESHelp import in_to_state, out_from_state, xor, gf_mul, get_columns


#
# Functions used in the AES Key Expansion routine
#
def RotWord(word):
    """
RotWord(word) -> word

RotWord takes four-byte input word and performs
a cyclic permutation. It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    return word[1:] + bytes([word[0]])


def SubWord(word):
    """
SubWord(word) -> word

SubWord that takes a four-byte input word and
applies an s-box to each of the four bytes to
produce an output word. It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    out = bytearray()
    for i in range(4):
        out.append(sbox[word[i]])
    return out


#
# AES Key expansion routine
#
def KeyExpansion(key, n_k, n_b=4):
    """
KeyExpansion(key, n_k, n_b=4) -> key list

KeyExpansion generates a series of Round Keys (key list)
from the Cipher Key (key).
n_k is the number of 32-bit words comprising the Cipher Key (key).
  For this standard, n_k = 4, 6, or 8.
n_b is the number of columns (32-bit words) comprising the state.
  For this standard, n_b = 4.
KeyExpansion is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    n_r = n_k + 6
    w = []
    key_list = key.to_bytes(n_k * 4, 'big')
    for i in range(0, n_k * 4, 4):
        w += [key_list[i:i + 4]]
    for i in range(n_k, (n_b * (n_r + 1))):
        temp = bytearray(w[i - 1])
        if i % n_k == 0:
            temp = SubWord(RotWord(temp))
            temp[0] = temp[0] ^ rcon[i // n_k]
        elif n_k > 6 and i % n_k == 4:
            temp = SubWord(temp)
        w += [xor(w[i - n_k], temp)]
    return w


#
# Functions used by AES Cipher
#
def AddRoundKey(state, key, n_b=4):
    """
AddRoundKey(state, key, n_b=4) -> state

Transformation in the Cipher and Inverse Cipher in which a
Round Key is added to the state using the xor operation. The
length of a Round Key equals the size of the State (i.e. for
n_b = 4, the Round Key length equals 128 bits/16 bytes).
It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    out = []
    s2 = get_columns(state)
    for i in range(n_b):
        out += [xor(s2[i], key[i])]
    return get_columns(out)


def SubBytes(state, n_b=4):
    """
SubBytes(state, n_b=4) -> state

SubBytes processes the state (a 2D array of longs) using a
nonlinear byte substitution table (Sbox) that operates on
each of the State bytes independently. It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    for col in range(n_b):
        for row in range(4):
            state[row][col] = sbox[state[row][col]]


def ShiftRows(state, n_b=4):
    """
ShiftRows(state, NB=4) -> state

ShiftRows processes the state (a 2D array of longs) by
cyclically shifting the last three rows of the state
by different offsets. It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    for i in range(1, n_b):
        state[i] = state[i][i:] + state[i][0:i]


def MixColumns(state, n_b=4):
    """
MixColumns(state, n_b=4) -> state

MixColumns takes all the columns of the state (2D array
of longs) and mixes their data independently of one another
to produce new columns. It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    out = [[0 for _ in range(4)] for _ in range(n_b)]
    for col in range(n_b):
        out[0][col] = \
            gf_mul(0x02, state[0][col]) ^ gf_mul(0x03, state[1][col]) ^ state[2][col] ^ state[3][col]
        out[1][col] = state[0][col] ^ gf_mul(0x02, state[1][col]) ^ gf_mul(0x03, state[2][col]) ^ state[3][col]
        out[2][col] = state[0][col] ^ state[1][col] ^ gf_mul(0x02, state[2][col]) ^ gf_mul(0x03, state[3][col])
        out[3][col] = gf_mul(0x03, state[0][col]) ^ state[1][col] ^ state[2][col] ^ gf_mul(0x02, state[3][col])
    return out


#
# AES Cipher
#
def Cipher(inp, keys, n_k, n_b=4):
    """
Cipher(inp, key, n_k, n_b = 4) -> state

Cipher performs a series of transformations that converts
plaintext (inp) to ciphertext using the expanded Cipher Key (keys).
n_k is the number of 32-bit words comprising the Cipher Key.
  For this standard, n_k = 4, 6, or 8.
n_b is the number of columns (32-bit words) comprising the state.
  For this standard, n_b = 4.
Cipher is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    state = in_to_state(inp)
    n_r = n_k + 6
    state = AddRoundKey(state, keys[0:n_b])
    for i in range(1, n_r):
        SubBytes(state)
        ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, keys[i * n_b:(i + 1) * n_b])
    SubBytes(state)
    ShiftRows(state)
    state = AddRoundKey(state, keys[n_r * n_b:(n_r + 1) * n_b])
    return out_from_state(state)


#
# Functions used by Inverse Cipher
#
def InvShiftRows(state):
    """
InvShiftRows(state) -> state

Transformation in the Inverse Cipher that is the inverse
of ShiftRows().  It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]


def InvSubBytes(state, n_b=4):
    """
InvSubBytes(state, n_b=4) -> state

InvSubBytes processes the state (a 2D array of longs) using a
nonlinear byte substitution table (SboxInv) that operates on
each of the State bytes independently. It is the inverse of
SubBytes. It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    for col in range(n_b):
        for row in range(4):
            state[row][col] = sboxInv[state[row][col]]


def InvMixColumns(state, n_b=4):
    """
MixColumns(state, n_b=4) -> state

MixColumns takes all the columns of the state (2D array
of longs) and mixes their data independently of one another
to produce new columns. The inverse of MixColumns.
It is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    out = [[0 for _ in range(4)] for _ in range(n_b)]
    for col in range(n_b):
        out[0][col] = \
            gf_mul(0x0e, state[0][col]) ^ \
            gf_mul(0x0b, state[1][col]) ^ \
            gf_mul(0x0d, state[2][col]) ^ \
            gf_mul(0x09, state[3][col])
        out[1][col] = \
            gf_mul(0x09, state[0][col]) ^ \
            gf_mul(0x0e, state[1][col]) ^ \
            gf_mul(0x0b, state[2][col]) ^ \
            gf_mul(0x0d, state[3][col])
        out[2][col] = \
            gf_mul(0x0d, state[0][col]) ^ \
            gf_mul(0x09, state[1][col]) ^ \
            gf_mul(0x0e, state[2][col]) ^ \
            gf_mul(0x0b, state[3][col])
        out[3][col] = \
            gf_mul(0x0b, state[0][col]) ^ \
            gf_mul(0x0d, state[1][col]) ^ \
            gf_mul(0x09, state[2][col]) ^ \
            gf_mul(0x0e, state[3][col])
    return out


#
# Inverse Cipher
#
def InvCipher(inp, keys, n_k, n_b=4):
    """
InvCipher(inp, key, n_k, n_b = 4) -> state

InvCipher performs a series of transformations that converts
ciphertext (inp) to plaintext using the Cipher Key (key).
n_k is the number of 32-bit words comprising the Cipher Key.
For this standard, n_k = 4, 6, or 8.
n_b is the number of columns (32-bit words) comprising the state.
For this standard, n_b = 4. InvCipher is defined in the
FIPS 197: Advanced Encryption Standard (November 26, 2001)."""
    state = in_to_state(inp)
    n_r = n_k + 6
    state = AddRoundKey(state, keys[n_r * n_b:(n_r + 1) * n_b])
    for i in range(n_r - 1, 0, -1):
        InvShiftRows(state)
        InvSubBytes(state)
        state = AddRoundKey(state, keys[i * n_b:(i + 1) * n_b])
        state = InvMixColumns(state)
    InvShiftRows(state)
    InvSubBytes(state)
    state = AddRoundKey(state, keys[0:n_b])
    return out_from_state(state)
