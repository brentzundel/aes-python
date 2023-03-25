def InToState(bytestring, Nb=4):
  '''
InToState(bytestring, Nb=4) -> state

InToState copies bytestream (bytes) to a state
(list of lists of ints) according to the scheme described
in section 3.4 ofthe Advanced Encryption Standard (FIPS 197).'''
  state = [[0 for row in range(4)] for col in range(Nb) ]
  for r in range(4):
    for c in range(Nb):
      state[r][c] = bytestring[r+4*c]
  return state


def OutFromState(state, Nb=4):
  '''
OutFromState(state, Nb=4) -> out

OutFromState copies state (2D array of longs) to out
(byte string) according to the scheme described
in section 3.4 ofthe Advanced Encryption Standard (FIPS 197).'''
  L = bytearray()
  for col in range(Nb):
    for row in range(4):
      L.append(state[row][col])
  return L
    

def padStrip(OS):
  '''
padStrip(OS) -> OS

padStrip removes the padding of '\x80\x00...' from
the end of the byte string OS.'''
  flag = True
  j = 0
  OSlen = len(OS)
  for i in range(1, OSlen):
    if OS[-i] == 0:
      flag = True and flag
      j += 1
    else:
      flag = False
      break
    if OS[OSlen-j-1] == 128:
      flag = True and flag
      break
  if flag:
    return OS[0:OSlen-j-1]
  else:
    return OS
 
# prints a list of longs as a hexadecimal string
def pilah(L):
  out = ''
  for x in map(hex, L):
    if len(x[2:4]) == 1:
       out += '0' + x[2:4]
    else:
       out +=  x[2:4]
  return out


# prints a 2D array of longs as a 2d hexadecimal block
def printState(state, length=4):
  for i in range(length):
    print(pilah(state[i]))


def prints(S):
  '''
prints(state) -> None

Prints the state to stdout.'''
  x = OutFromState(S)
  for i in x:
    print(hex(i)[2:], end='')
  print()


def xor(byteString1, byteString2):
  '''
xor(byteString1, byteString2) -> bytes

xor performs the exclusive-or operation on two byte strings.'''
  length = len(byteString1)
  if length != len(byteString2):
    raise Exception("Byte strings are of different lengths")
  z = bytearray()
  for i in range(length):
    z.append(byteString1[i] ^ byteString2[i])
  return z


def MSB(s, OS):
  '''
MSB(s, OS) -> OS

MSB returns the s most significant bits from OS.'''
  B = s//8
  return OS[0:B]


 
def LSB(s, OS):
  '''
LSB(s, OS) -> OS

LSB returns the s least significant bits from OS.'''
  B = s//8
  if s == 0:
    return b''
  else:
    return OS[-B:]


def SplitList(ITER, size=10):
  '''
SplitList(ITER, size=10) -> list of iterables

SplitList converts an iterable into a
list of iterables of length bits.'''
  size = bits//8
  out = []
  i = 0
  OSLen = len(OS)
  while i < OSLen:
    out += [OS[i:i+size]]
    i += size
  return out
