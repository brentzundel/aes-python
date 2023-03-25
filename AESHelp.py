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
in section 3.4 ofthe Advanced Encryption Standard (FIPS 197)."""
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
def pilah(longs):
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
        print(pilah(state[i]))


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

lsb returns the s least significant bits from os."""
    b = s // 8
    if s == 0:
        return b''
    else:
        return os[-b:]
