import hashlib
import numpy as geek
from Crypto.Cipher import Blowfish
from Crypto import Random
from struct import pack

def protokol(B):

    print("======================================Ceking Menggunakan HasingMD5=========================================")
    has1 = hashlib.md5(str.encode(B))
    print("Hasing plaintext Masukan : ", end="")
    print(has1.digest())


#==============================================Curva Eliptik Enkripsi==================================================#
    print("========================================Curva Eliptik Enkripsi==============================================")

    print("Elliptic Curve General Form:\t y^2 mod n=(x^3  + a*x + b)mod n\nEnter 'n':")


    def polynomial(LHS, RHS, n):
        for i in range(0, n):
            LHS[0].append(i)
            RHS[0].append(i)
            LHS[1].append((i * i * i + a * i + b) % n)
            RHS[1].append((i * i) % n)

    def points_generate(arr_x, arr_y, n):
        count = 0
        for i in range(0, n):
            for j in range(0, n):
                if (LHS[1][i] == RHS[1][j]):
                    count += 1
                    arr_x.append(LHS[0][i])
                    arr_y.append(RHS[0][j])
        return count

    # main
    n = 193  # Bilangan Prima
    LHS = [[]]
    RHS = [[]]
    LHS.append([])
    RHS.append([])
    a = 3
    print("value of 'a':", a)
    b = 1
    print("value of 'b':", b)
    # Polynomial
    polynomial(LHS, RHS, n)

    arr_x = []
    arr_y = []
    # Generating base points
    count = points_generate(arr_x, arr_y, n)

    # Print Generated Points
    print("Generated points are:")
    for i in range(0, count):
        print(i + 1, " (", arr_x[i], ",", arr_y[i], ")\n")

    # Calculation of Base Point
    bx = arr_x[5]
    by = arr_y[0]
    print("Titik Kurva Awal:\t(", bx, ",", by, ")\n")

    print("Enter the random number 'd' i.e. Private key of Sender (d<n):")
    d = 3
    print("Private Key untuk penerima : ", d)
    if (d >= n):
        print("'d' harus lebih kecil woy 'n'.")
    else:
        # Q i.e. sender's public key generation
        Qx = d * bx
        Qy = d * by
        print("Public key :\t(", Qx, ",", Qy, ")\n")

        # Encrytion
        k = d
        if (k >= n):
            print("'k' harus lebih kecil 'n'")
        else:

            # Cipher text 1 generation
            C1x = k * Qx
            C1y = k * Qy
            print("Titik KKP (Titik Enkripsi) :\t(", C1x, ",", C1y, ")\n")

            # Cipher text 2 generation
            C2x = k * bx
            C2y = k * by
            print("Titik KP (Titik Dekripsi) :\t(", C2x, ",", C2y, ")\n")

            ### Enkripsi titik KP ###
            Et1 = chr(C2x)
            Et2 = chr(C2y)
            print("Enkripsi titik KP =\t(", Et1, ",", Et2, ")\n")

            ### Enkripsi Titik KKP ####
            Ek = C1x
            print("Titik Absis KKP = ", Ek)
            Eb = [bin(Ek)[2:].zfill(8)]
            Ebb = ','.join(Eb)
            print("Titik Absis KKP dalam biner = ", Eb)

            ### Masukan PlainText ###
            print("Enter the message to be sent:\n")
            B = B

            ## Merubah Ke Integer ##
            In = [ord(c) for c in B]
            print(In)

            ## Merubah Ke Biner ##
            Bi = [bin(x)[2:].zfill(8) for x in In]
            Bii = ','.join(Bi)
            print(Bii)

            ## Melakukan XOR Pada Titik Absis KKP ##
            data = Bii
            key = Ebb

            #### Melakukan XOR ####4

            in_arr1 = In
            in_arr2 = [Ek]

            print("Input array1 : ", in_arr1)
            print("Input array2 : ", in_arr2)

            out_arr = geek.bitwise_xor(in_arr1, in_arr2)
            print("Output array after bitwise_xor: ", out_arr)

            Ekb = [bin(x)[2:].zfill(8) for x in out_arr]
            print("Hasil Xor Binner =", Ekb)

            ###### Chiper Text #######
            Dekripsi_xor = ''.join([chr(int(x, 2)) for x in Ekb])
            print("Hasil Xor =", Dekripsi_xor)

            ##### Enkripsi Plaintext + Header #####
            q = Et1
            w = Et2
            e = Dekripsi_xor
            t = '#'
            z = q + t + w + t + e
            print("Hasil ENKRIPSI =", z)

    #==============================================Blow fISH Enkripsi==================================================#
    print("=========================================Blow fISH Enkripsi=================================================")
    bs = Blowfish.block_size
    key = b'01110000'
    iv = Random.new().read(bs)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = str_to_bytes = str.encode(z)
    print("Hasil enkripsi ke byte : ",str_to_bytes)
    plen = bs - divmod(len(plaintext), bs)[1]
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    msg_chip = iv + cipher.encrypt(plaintext + padding)
    print("Chiper Text Protocol :", msg_chip)

    #=================================================Blow fISH Dekripsii==============================================#
    print("=========================================Blow fISH Dekripsi=================================================")
    bs = Blowfish.block_size
    key = b'10000000'
    ciphertext = msg_chip
    iv = ciphertext[:bs]
    ciphertext = ciphertext[bs:]

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    msg = cipher.decrypt(ciphertext)

    last_byte = msg[-1]
    msg = msg[:- (last_byte if type(last_byte) is int else ord(last_byte))]

    decoded_bytes = str_to_bytes.decode()
    print("plaintext :", decoded_bytes)

#=================================================Curva Eliptik Dekripsi===============================================#
    print("=======================================Curva Eliptik Dekripsi===============================================")

##### Dekripsi Pemisahan Header#####
    Dz=decoded_bytes[4:]
    print("Chiper yang sudah di hilangkan headernya=", Dz)

    ###### DEKRIPSI ENKRIPSI #######
    bz = [ord(c) for c in Dz]
    print(bz)
    ###### INTEGER KE BINER #######
    bzi = [bin(x)[2:].zfill(8) for x in bz]
    print(bzi)

     ###### Titik kP ######
    Kt1= k*C2x
    Kt2= k*C2y
    print("Titik KP (Titik Dekripsi) :\t(", Kt1, ",", Kt2, ")\n")

    ### Enkripsi Titik KKP ####
    Edt = Kt1
    print("Titik Absis KKP = ", Edt)
    Edtb = [bin(Edt)[2:].zfill(8)]
    Edtbb = ','.join(Edtb)
    print("Titik Absis KKP dalam biner = ", Edtbb)

    #### Melakukan XOR ####4

    Dek_arr1 = bz
    Dek_arr2 = [Edt]

    print("Input array1 : ", Dek_arr1)
    print("Input array2 : ", Dek_arr2)

    Fin_arr = geek.bitwise_xor(Dek_arr1, Dek_arr2)
    print("Output array after bitwise_xor: ", Fin_arr)

    Pl = [bin(x)[2:].zfill(8) for x in Fin_arr]
    print("Hasil Xor Binner =",Pl)

    ###### Menjadikan Plaintext #######
    Plaintex_ecc = ''.join([chr(int(x, 2)) for x in Pl])
    print("text asli adalah =",Plaintex_ecc)


#===================================================CEKING PESAN=======================================================#
    print("============================================CEKING PESAN===================================================")

    has2 = hashlib.md5(str.encode(Plaintex_ecc))
    print("Hasing plaintext Keluaran : ", end="")
    print(has2.digest())

    if (has2.digest()== has1.digest()):
        print("DATA SAMA")
    else:
        print("DATA TIDAK SAMA !!!!!!")

    print("===========================================================================================================")




if __name__ == "__main__":

 while (True):
################## ceking Hasing #################
    print("Protokol Keamanan Data menggunakan Algoritma Eliptic Curve dan Blowfish")
    print("Masukan plaintext : ")
    B= input()
    protokol(B)






