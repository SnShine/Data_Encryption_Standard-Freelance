import sys, time

#to know which python version is installed
pythonVersion = sys.version_info[0]

class base(object):
    def __init__(self):
        #set the size of the block to encrypt/decrypt the data
        self.block_size = 8

    def getKey(self):
        """returns key used to encrypt/decrypt"""
        return self.__key

    def setKey(self, key):
        """will set the key used for encrypting/decrypting"""
        self.__key = key

    def padData(self, data):
        #length of string to be added to data to make its length a multiple of 8       
        pad_len = 8 - (len(data) % self.block_size)
        
        #add characters if python version is 2
        if pythonVersion < 3:
            data += pad_len * chr(pad_len)
        #add bytes of data if python version using is 3
        else:
            data += bytes([pad_len] * pad_len)

        return data

    def unpadData(self, data):
        #used for unpadding the data
        if not data:
            return data
        
        #use the function ord to return unicode integer while using python version 2
        if pythonVersion< 3:
            pad_len = ord(data[-1])
        #python 3 automatically converts it into integer
        else:
            pad_len = data[-1]
        #then remove the extra data we attached at the end of the string
        data = data[:-pad_len]

        return data


class des(base):
    #initial permutation(IP)
    ip = [57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]
    #final permutation(FP)
    fp = [
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
        32,  0, 40,  8, 48, 16, 56, 24
    ]

    
    #expansion function table(E)
    expansion_table = [
        31,  0,  1,  2,  3,  4,
         3,  4,  5,  6,  7,  8,
         7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    ]

    
    #32-bit permutation function P used on the output of the S-boxes
    p = [
        15, 6, 19, 20, 28, 11, 27, 16,
        0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24
    ]

    
    #PC1 for des
    pc1 = [56, 48, 40, 32, 24, 16,  8,
          0, 57, 49, 41, 33, 25, 17,
          9,  1, 58, 50, 42, 34, 26,
         18, 10,  2, 59, 51, 43, 35,
         62, 54, 46, 38, 30, 22, 14,
          6, 61, 53, 45, 37, 29, 21,
         13,  5, 60, 52, 44, 36, 28,
         20, 12,  4, 27, 19, 11,  3
    ]
    #PC2 for des
    pc2 = [
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    
    #S-boxes
    sbox = [
        #Sbox1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        #Sbox2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        #Sbox3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        #Sbox4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        #Sbox5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        #Sbox6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        #Sbox7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        #Sbox8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]

   
    #left-rotations in key-schedule
    left_rotations = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]


    #type of crypting
    ENCRYPT= 0x00
    DECRYPT= 0x01

    #initialisation
    def __init__(self, key):
        base.__init__(self)
        self.key_size = 8

        #left and right parts of string
        self.L = []
        self.R = []
        #16 sub-keys of 48 bits each
        self.Kn = [[0]* 48]* 16
        self.final = []

        self.setKey(key)

    def setKey(self, key):
        """will set the key used for encrypting/decrypting"""
        base.setKey(self, key)
        self.create_sub_keys()

    def String_to_BitList(self, data):
        """turn the string data, into a list of bits"""
        if pythonVersion < 3:
            #turn the strings into integers. python3 uses a bytes
            #class, which already has this behaviour.
            data= [ord(c) for c in data]
        
        l= len(data) * 8
        result= [0] * l
        pos= 0
        for ch in data:
            i = 7
            while i>= 0:
                if ch& (1<< i)!= 0:
                    result[pos]= 1
                else:
                    result[pos]= 0
                pos+= 1
                i-= 1

        return result

    def BitList_to_String(self, data):
        """turn the list of bits into a string"""
        result = []
        pos = 0
        c = 0
        while pos < len(data):
            c+= data[pos]<< (7- (pos% 8))
            if (pos% 8)== 7:
                result.append(c)
                c= 0
            pos+= 1

        if pythonVersion< 3:
            return ''.join([ chr(c) for c in result ])
        else:
            return bytes(result)

    def permutate(self, table, block):
        """Permutate this block with the specified table"""
        return list(map(lambda x: block[x], table))

    def create_sub_keys(self):
        """create 16 subkeys of 48 bits of length from given key of length of 56 bits"""
        key = self.permutate(des.pc1, self.String_to_BitList(self.getKey()))
        i = 0
        #split the key into left and right sections, each of 28 bits of length
        self.L= key[:28]
        self.R= key[28:]
        print("\nPrinting all 16 sub-keys used in 16 stages...")
        while i< 16:
            j= 0
            #perform left shifts. left most bit 
            while j< des.left_rotations[i]:
                self.L.append(self.L[0])
                del self.L[0]

                self.R.append(self.R[0])
                del self.R[0]

                j+= 1

            #create one of the 16 subkeys through pc2 permutation
            self.Kn[i]= self.permutate(des.pc2, self.L + self.R)
            print "\tSub-Key "+str(i)+" :", ''.join(self.BitList_to_String(self.Kn[i])) 

            i+= 1

    #important part of encryption algorithm
    def des_crypt(self, block, crypt_type):
        """
        Takes a block of data (8 bytes in ths case) as input
        Runs bit-manipulation on block of data following 
        DES algorithm (16 stages).
        """
        #permutating with initial permutation block
        block = self.permutate(des.ip, block)
        #dividing into left and right blockes
        self.L = block[:32]
        self.R = block[32:]

        #encryption starts from Kn[1] through to Kn[16]
        if crypt_type== des.ENCRYPT:
            iteration= 0
            iteration_change= 1
        #decryption starts from Kn[16] down to Kn[1]
        else:
            iteration= 15
            iteration_change= -1

        i= 0
        print("\tPrinting value of current block in all of 16 stages...")
        while i< 16:
            #get a copy of R[i-1] which will later become L[i]
            #this is why this method is called as criss-cross method
            tempR= self.R[:]

            #permutate R[i-1] with expansion table
            self.R= self.permutate(des.expansion_table, self.R)

            #exclusive or R[i-1] with K[i], create B[1] to B[8] whilst here
            self.R= list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
            B= [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]

            #permutate B[1] to B[8] using the S-Boxes
            j= 0
            Bn= [0]* 32
            pos= 0
            while j< 8:
                #work out the offsets
                m= (B[j][0]<< 1)+ B[j][5]
                n= (B[j][1]<< 3)+ (B[j][2]<< 2) + (B[j][3]<< 1) + B[j][4]

                #find the permutation value
                v= des.sbox[j][(m<< 4)+ n]

                #turn value into bits, add it to result: Bn
                Bn[pos]= (v& 8)>> 3
                Bn[pos+ 1]= (v& 4)>> 2
                Bn[pos+ 2]= (v& 2)>> 1
                Bn[pos+ 3]= v& 1

                pos += 4
                j += 1

            #permutate the concatination of B[1] to B[8] (Bn)
            self.R = self.permutate(des.p, Bn)

            #XOR with L[i-1]
            self.R = list(map(lambda x, y: x ^ y, self.R, self.L))

            #new L[i] is R[i-1]
            self.L = tempR

            i+= 1
            iteration+= iteration_change

            print "\tStage "+str(i)+" :", ''.join(self.BitList_to_String(self.permutate(des.fp, self.R+ self.L)))
        
        # Final permutation of R[16] and L[16]
        self.final= self.permutate(des.fp, self.R + self.L)
        #print("final", ''.join(self.BitList_to_String(self.final)))
        return self.final


    #data to be encrypted/decrypted
    def crypt(self, data, crypt_type):
        """
        Crypt the data in blocks, running it through des_crypt()
        If the input data has more bytes than 8, we will divide it into
        blocks with 8 bytes of data. Then we will run des_crypt function 
        on every block of data to encryp/ decrypt the data.
        """

        #Error, check the data
        if not data:
            return ''
        if len(data)% self.block_size!= 0:
            #decryption works only on data blocks of 8 bytes of length.
            if crypt_type== des.DECRYPT:
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n.")
            if not self.getPadding():
                raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n. Try setting the optional padding character")
            else:
                data+= (self.block_size - (len(data) % self.block_size)) * self.getPadding()

        #split the data into blocks, crypting each one seperately
        i = 0
        dict = {}
        result = []
        while i < len(data):                
            block = self.String_to_BitList(data[i:i+8])
            print("\nCurrent block: "+str(i/8))
            processed_block = self.des_crypt(block, crypt_type)
            print "\tProcessed block "+str(i/8)+": ", ''.join(self.BitList_to_String(processed_block))

            #append the resulting crypted block to our list
            result.append(self.BitList_to_String(processed_block))
            i += 8

        #return the full crypted string
        if pythonVersion < 3:
            return ''.join(result)
        else:
            return bytes.fromhex('').join(result)

    def encrypt(self, data):
        """
        """
        data = self.padData(data)
        return self.crypt(data, des.ENCRYPT)

    def decrypt(self, data):
        """
        """
        data = self.crypt(data, des.DECRYPT)
        return self.unpadData(data)

if __name__== "__main__":
    
    def detectUnicode(data):
        if pythonVersion < 3:
            if isinstance(data, unicode):
                raise ValueError("Only works with bytes, not Unicode strings!")
        else:
            if isinstance(data, str):
                # Only accept ascii unicode values.
                try:
                    return data.encode('ascii')
                except UnicodeEncodeError:
                    pass
                raise ValueError("Only works with encoded strings, not with Unicode strings!")
        return data

    
    if len(sys.argv)!= 3:
        print("Error occured! See below how to use.\nUsage: python main.py <message to encrypt in quotes> <key to use in quotes>")
        sys.exit()

    out_file= open("out.txt", "w")

    #sys.srgv[1] is data
    #sys.argv[2] is key

    data= sys.argv[1]
    data= detectUnicode(data)

    key= sys.argv[2]
    if len(key) != 8:
        print("Invalid key size. The length of key should be 8 bytes")
        sys.exit()
    key= detectUnicode(key)

    k= des(sys.argv[2])

    #encrypting the data and saving to enc_data
    enc_data= k.encrypt(data)
    print("\nEncrypted data...")
    print(enc_data)
    out_file.write(enc_data)
    print("\n")
    out_file.write("\n")

    #decrypting the encrypted data
    dec_data= k.decrypt(enc_data)
    print("\nDecrypted data...")
    print(dec_data)
    out_file.write(dec_data)
    print("\n")
    out_file.write("\n")

    out_file.close()
