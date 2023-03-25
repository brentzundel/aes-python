##
#
# Test Vectors (from NIST Special Publication 800-32A)
#
##

#
# test file is equivalent to the following four bytes strings:
#
t1 = b'\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a'
t2 = b'\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51'
t3 = b'\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef'
t4 = b'\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10'
teststring = t1 + t2 + t3 + t4


#
# that string can be used as an argument in the following function,
#   to create the file:
#
def toFile(teststr):
    fout = open('test', 'wb')
    fout.write(teststr)
    fout.close


#
# test keys:
#
key128 = 0x2b7e151628aed2a6abf7158809cf4f3c
key192 = 0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
key256 = \
    0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4


##
#
# A Function for comparing two files, byte by byte
#
##
def testFiles(file1, file2):
    '''
testFiles(file1, file2) -> bool

testFiles compares the contents of two files and returns
True if they are identical.'''
    in1 = open(file1, 'rb')
    in2 = open(file2, 'rb')
    x = in1.read(100)
    while x != b'':
        if x != in2.read(100):
            in1.close()
            in2.close()
            return False
        x = in1.read(100)
    in1.close()
    in2.close()
    return True
