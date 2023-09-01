import copy


class AES:
    # constructor 
    def __init__(self, inp, key):
        inp = inp.replace(' ', '')
        key = key.replace(' ', '')
        if len(key) == 32: self.nr, self.nk = 10, 4
        elif len(key) == 48: self.nr, self.nk = 12, 6
        elif len(key) == 64: self.nr, self.nk = 14, 8
        else: raise ValueError("key length should be 16 24 or 32")
        self.s = self.to2dArray(inp) # state
        self.s_init = self.to2dArray(inp) # testing
        self.k = self.to2dArray(key) # key
        self.rk = self.SplitKey(self.KeyExpansion()) # round keys        
        self.r = [] # rounds (testing)
        self.ir = [] # inverse rounds (testing)

    # key to 2d array (state should be initialized as matrix)
    def to2dArray(self, str):
        hex = [str[i:i+2] for i in range(0, len(str), 2)]

        iter = len(str) // 8 
        arr = [[0] * 4 for i in range(iter)]

        for c in range(iter):
            for r in range(4):
                arr[c][r] = int(hex[r + 4 * c], 16)
        return arr

    # turn 2d array back to bytes
    def toString(self, arr):
        str = ''
        for c in range(len(arr)):
            for r in range(4):
                str += "{:02x}".format(arr[c][r])
        return str

    # encoder function 
    def Cipher(self):
        self.r.append("CIPHER (ENCRYPT):")
        self.r.append(f"round[ 0].input    {self.toString(copy.deepcopy(self.s))}")
        self.r.append(f"round[ 0].k_sch    {self.toString(copy.deepcopy(self.rk[0]))}")
        self.r.append(f"round[ 1].start    {self.toString(copy.deepcopy(self.AddRoundKey(0)))}")
     
        for i in range(1, self.nr): 
            self.r.append(f"round[{f' {i}' if i < 10 else i}].s_box    {self.toString(copy.deepcopy(self.SubBytes()))}")
            self.r.append(f"round[{f' {i}' if i < 10 else i}].s_row    {self.toString(copy.deepcopy(self.ShiftRows()))}")
            self.r.append(f"round[{f' {i}' if i < 10 else i}].m_col    {self.toString(copy.deepcopy(self.MixColumns()))}")
            self.r.append(f"round[{f' {i}' if i < 10 else i}].k_sch    {self.toString(copy.deepcopy(self.rk[i]))}")
            self.r.append(f"round[{f' {i+1}' if i < 9 else i+1}].start    {self.toString(copy.deepcopy(self.AddRoundKey(i)))}")

        self.r.append(f"round[{self.nr}].s_box    {self.toString(copy.deepcopy(self.SubBytes()))}")
        self.r.append(f"round[{self.nr}].s_row    {self.toString(copy.deepcopy(self.ShiftRows()))}")
        self.r.append(f"round[{self.nr}].k_sch    {self.toString(copy.deepcopy(self.rk[self.nr]))}")
        self.r.append(f"round[{self.nr}].output   {self.toString(copy.deepcopy(self.AddRoundKey(self.nr)))}")
        return self.s

    # S-box table for SubBytes (fig 7)
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    # substitution step, uses table defined above
    def SubBytes(self):
        for c in range(4):
            for r in range(4):
                self.s[c][r] = self.sbox[self.s[c][r]]    
        return self.s


    # permutation step 1, cyclically shifts last 3 rows by incrementing amounts (fig 8)
    def ShiftRows(self):
        for r in range(4):
            for i in range(r):
                temp = self.s[0][r]
                for c in range(1, 4):
                    self.s[c - 1][r] = self.s[c][r]
                self.s[3][r] = temp
        return self.s
    
    # helper function for MixColumns & inverse, needed for galois field multiplication (sec 5.1.3)
    def GF(self, s, g):
        p = 0
        for i in range(8):
            if g & 1: 
                p ^= s
            flag = s & 0x80
            s <<= 1
            if flag:
                s ^= 0x1b
            g >>= 1
        return p % 256

    # permutation step 2, cycle through columns and multiply by finite field matrix (sec 5.1.3)
    def MixColumns(self):
        for c in range(4):
            s0 = self.s[c][0]
            s1 = self.s[c][1]
            s2 = self.s[c][2]
            s3 = self.s[c][3]

            self.s[c][0] = self.GF(s0, 0x02) ^ self.GF(s1, 0x03) ^ s2 ^ s3
            self.s[c][1] = s0 ^ self.GF(s1, 0x02) ^ self.GF(s2, 0x03) ^ s3
            self.s[c][2] = s0 ^ s1 ^ self.GF(s2, 0x02) ^ self.GF(s3, 0x03)
            self.s[c][3] = self.GF(s0, 0x03) ^ s1 ^ s2 ^ self.GF(s3, 0x02)
        return self.s

    # subkey is added to state with bitwise XOR (fig 10)
    # no separate inverse function needed as it operates solely on XOR 
    def AddRoundKey(self, i):
        for c in range(4):
            for r in range (4):
                self.s[c][r] ^= self.rk[i][c][r]
        return self.s
    
    
    # round constant for xor 
    rcon = [
        [0x00, 0x00, 0x00, 0x00], [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00], 
        [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00], 
        [0x1B, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00], [0x6C, 0x00, 0x00, 0x00], 
        [0xD8, 0x00, 0x00, 0x00], [0xAB, 0x00, 0x00, 0x00], [0x4D, 0x00, 0x00, 0x00], 
        [0x9A, 0x00, 0x00, 0x00], [0x2F, 0x00, 0x00, 0x00], [0x5E, 0x00, 0x00, 0x00]
    ]
    
    # key expansion sub function - 1 of 2
    def SubWord(self, w):
        for i in range(4):
            w[i] = self.sbox[w[i]]
        return w
    
    # key expansion sub function - 2 of 2
    def RotWord(self, w):
        w.append(w.pop(0))
        return w 

    # make round keys with cipher key
    def KeyExpansion(self):
        w = copy.deepcopy(self.k)
        i = self.nk
        while i < 4 * (self.nr + 1):
            temp = w[i-1][:]
            if (i % self.nk == 0):
                temp = self.SubWord(self.RotWord(temp)) 
                xor = []
                for t, r in zip(temp, self.rcon[i//self.nk]):
                    xor.append(t ^ r)
                temp = xor[:]
            elif (self.nk > 6 and i % self.nk == 4):
                temp = self.SubWord(temp)
            xor = []
            for prev, pres in zip(w[i - self.nk], temp):
                xor.append(prev ^ pres)
            w.append(xor)
            i += 1
        return w
    
    # group words into subkeys
    def SplitKey(self, w):
        rk = []
        for i in range(self.nr + 1):
            rk.append([w[j] for j in range(i*4, i*4+4)])
        return rk
    
    # inverse cipher, decoder
    def InvCipher(self):
        self.ir.append("INVERSE CIPHER (DECRYPT):")
        self.ir.append(f"round[ 0].iinput   {self.toString(copy.deepcopy(self.s))}")
        self.ir.append(f"round[ 0].ik_sch   {self.toString(copy.deepcopy(self.rk[self.nr]))}")
        self.ir.append(f"round[ 1].istart   {self.toString(copy.deepcopy(self.AddRoundKey(self.nr)))}")
     
        for i in range(1, self.nr): 
            self.ir.append(f"round[{f' {i}' if i < 10 else i}].is_row   {self.toString(copy.deepcopy(self.InvShiftRows()))}")            
            self.ir.append(f"round[{f' {i}' if i < 10 else i}].is_box   {self.toString(copy.deepcopy(self.InvSubBytes()))}")
            self.ir.append(f"round[{f' {i}' if i < 10 else i}].ik_sch   {self.toString(copy.deepcopy(self.rk[self.nr-i]))}")            
            self.ir.append(f"round[{f' {i}' if i < 10 else i}].ik_add   {self.toString(copy.deepcopy(self.AddRoundKey(self.nr-i)))}")
            self.ir.append(f"round[{f' {i+1}' if i < 9 else i+1}].istart   {self.toString(copy.deepcopy(self.InvMixColumns()))}")

        self.ir.append(f"round[{self.nr}].is_row   {self.toString(copy.deepcopy(self.InvShiftRows()))}")
        self.ir.append(f"round[{self.nr}].is_box   {self.toString(copy.deepcopy(self.InvSubBytes()))}")
        self.ir.append(f"round[{self.nr}].ik_sch   {self.toString(copy.deepcopy(self.rk[0]))}")
        self.ir.append(f"round[{self.nr}].ioutput  {self.toString(copy.deepcopy(self.AddRoundKey(0)))}")
        return self.s    
    
    # inverse of ShiftRows (fig 13)
    def InvShiftRows(self):
        for r in range(4):
            for i in range(r):
                temp = self.s[3][r]
                for c in range(2, -1, -1):
                    self.s[c + 1][r] = self.s[c][r]
                self.s[0][r] = temp
        return self.s
    

    # Inverse S-box table for InvSubBytes (fig 14)
    invSbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    # inverse of SubBytes
    def InvSubBytes(self):
        for c in range(4):
            for r in range(4):
                self.s[c][r] = self.invSbox[self.s[c][r]]
        return self.s
    
    # inverse of MixColumns (sec 5.3.3)
    def InvMixColumns(self):
        for c in range(4):
            s0 = self.s[c][0]
            s1 = self.s[c][1]
            s2 = self.s[c][2]
            s3 = self.s[c][3]

            self.s[c][0] = self.GF(s0, 0x0e) ^ self.GF(s1, 0x0b) ^ self.GF(s2, 0x0d) ^ self.GF(s3, 0x09)
            self.s[c][1] = self.GF(s0, 0x09) ^ self.GF(s1, 0x0e) ^ self.GF(s2, 0x0b) ^ self.GF(s3, 0x0d)
            self.s[c][2] = self.GF(s0, 0x0d) ^ self.GF(s1, 0x09) ^ self.GF(s2, 0x0e) ^ self.GF(s3, 0x0b)
            self.s[c][3] = self.GF(s0, 0x0b) ^ self.GF(s1, 0x0d) ^ self.GF(s2, 0x09) ^ self.GF(s3, 0x0e)
        return self.s
        
    # for testing    
    def getRk(self):
        return self.rk

    # for testing
    def parseWords(self, rk):
        return rk[0:8] + ' ' + rk[8:16] + ' ' + rk[16:24] + ' ' + rk[24:32]
    
    # for testing
    def tester(self):
        header = (
            f"AES-{self.nk * 32} (Nk={self.nk}, Nr={self.nr})\n"
            f"PLAINTEXT:  {self.toString(self.s_init)}\n"
            f"KEY:        {self.toString(self.k)}"
        )
        return header + '\n\n' + '\n'.join(self.r) + '\n\n' + '\n'.join(self.ir)      
