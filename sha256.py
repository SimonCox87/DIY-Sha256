# Hash algorithms are easy to do one way, but essentially impossible to do in reverse. For example, if you hash something simple, 
# like password123, it will give you a long code, unique to that word or phrase. Ideally, there's no way to do this in reverse. You 
# can't take the hash code and go back to the word or phrase you started with.

# Make a function that returns the SHA-256 secure hash for a given string. The hash should be formatted in a hexadecimal digit string.
# Examples

# get_sha256_hash("password123") ➞ "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"

# get_sha256_hash("Fluffy@home") ➞ "dcc1ac3a7148a2d9f47b7dbe3d733040c335b2a3d8adc7984e0c483c5b2c1665"

# get_sha256_hash("Hey dude!") ➞ "14f997f08b8ad032dcb274198684f995d34043f9da00acd904dc72836359ae0f"

# Notes

# Bonus if you can do it without importing any libraries ;)

#SHA256 Encryption without using Python libraries 
# Resources used to complete this challenge:
#   - https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf
#   - https://www.youtube.com/watch?v=orIgy2MjqrA
#   - https://www.youtube.com/watch?v=f9EbD6iY9zI
#   - https://www.youtube.com/watch?v=9xs4eWOAG7Y

# h-value constants derived from the first 8 prime numbers
# (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
h = [
'6a09e667','bb67ae85','3c6ef372','a54ff53a',
'510e527f','9b05688c','1f83d9ab','5be0cd19'
]

# k-value constants derived from the first 64 prime numbers
# (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
k = [
'428a2f98','71374491','b5c0fbcf','e9b5dba5',
'3956c25b','59f111f1','923f82a4','ab1c5ed5',
'd807aa98','12835b01','243185be','550c7dc3',
'72be5d74','80deb1fe','9bdc06a7','c19bf174',
'e49b69c1','efbe4786','0fc19dc6','240ca1cc',
'2de92c6f','4a7484aa','5cb0a9dc','76f988da',
'983e5152','a831c66d','b00327c8','bf597fc7',
'c6e00bf3','d5a79147','06ca6351','14292967',
'27b70a85','2e1b2138','4d2c6dfc','53380d13',
'650a7354','766a0abb','81c2c92e','92722c85',
'a2bfe8a1','a81a664b','c24b8b70','c76c51a3',
'd192e819','d6990624','f40e3585','106aa070',
'19a4c116','1e376c08','2748774c','34b0bcb5',
'391c0cb3','4ed8aa4a','5b9cca4f','682e6ff3',
'748f82ee','78a5636f','84c87814','8cc70208',
'90befffa','a4506ceb','bef9a3f7','c67178f2'
]

#Function for pre-processing and creating the message blocks
def padding(txt):
    # Create the message by converting the character into it's corresponding binary representation (ASCII).  Add the required number
    # of "0"s to ensure that the length of this binary is 8 bits.
    mess = "".join(format(ord(i),'08b') for i in txt) + "1"
    # Separate the message into 512 bit blocks
    blocks = [mess[i:i+512] for i in range(0,len(mess),512)]

    #Padding the blocks which is determined by the length of the last block
    if len(blocks[-1]) in range(448,512):
        blocks[-1] = blocks[-1] + "0" * (512 - len(blocks[-1]))
        blocks.append(format(len(txt)*8,'0512b'))
    else:
        blocks[-1] = blocks[-1] + "0" * (448 - len(blocks[-1])) + format(len(txt)*8,'064b')
    
    # Split each block into 32 bit chunks
    return [[i[j:j+32] for j in range(0,512,32)] for i in blocks]


# Develop Sigma values to help compute values w16 ... w63
def sigmaShift(bin, shift):
    # Creates a dictionary with the key representing the bit's new shifted position and the value representing the actual value
    # of the bit.
    newPosition = {(i + shift)%32 : bin[i] for i in range(len(bin))}
    # Join the values of the dictionary by their new sorted positions.
    return "".join(i[1] for i in sorted(newPosition.items(), key=lambda x: x[0]))

# Generates the modulo 2 of shifted bin + bin(rotated(1)) + bin(rotated(2))
def sigmaFinal(bin, shift, rRot1, rRot2):
    # Shifts the binary by the number used in the function.  Bits are removed from the end of the string and the binary
    # is padded with 0's according to the number of bits that have been shifted.
    bin = ("0" * shift) + bin[:-shift]
    # Xor (%2) of shifted binary and the two right rotated binaries
    return "".join(str(i%2) for i in [int(bin[i]) + int(rRot1[i]) + int(rRot2[i]) for i in range(len(bin))])

# Add two or more 32bit binary strings together and modulo 2**32 to ensure that the binaries remain 32 bit
def addBin(*args):
    # Create a list of the reversed binaries.  So that we can loop over them.
    wRev = list(map(lambda x: x[::-1],args))
    # Initiate a list to contain the decimal values of each binary, so that we can find the sum of these.
    decs = [0 for i in wRev]
    
    # Begin the loop.  If bit == "1" dec[i] += m.  With every loop through j (32 for 32 bits) m*= 2.  m reset to 1 after a
    # full loop through j. 
    for i in range(len(decs)):
        for j in range(32):
            if wRev[i][j] == "1":
                decs[i] += 2 ** j
    
    # Return formattted binary for the sum of decs %(2**32) to ensure that the new binary is still comprised of 32 bits
    return format(sum(decs)%(2**32),'032b') 

# Function to convert hex numbers into a binary form
def hexToBin(hex):
    hexBinDict = {
        "0":"0000", "1":"0001", "2":"0010", "3":"0011", 
        "4":"0100", "5":"0101", "6":"0110", "7":"0111", 
        "8":"1000", "9":"1001", "a":"1010", "b":"1011", 
        "c":"1100", "d":"1101", "e":"1110", "f":"1111"
        }
    return "".join([hexBinDict[i] for i in hex])

# Function to covert 32bit binary into hex
def binToHex(bin):
    binHexDict = {
        "0000":"0", "0001":"1", "0010":"2", "0011":"3", 
        "0100":"4", "0101":"5", "0110":"6", "0111":"7", 
        "1000":"8", "1001":"9", "1010":"a", "1011":"b", 
        "1100":"c", "1101":"d", "1110":"e", "1111":"f"
    }
    return "".join(binHexDict[i] for i in [bin[i:i+4] for i in range(0,32,4)])

# Function to perform the choose (ch) operation(e,f,g)
def ch(e,f,g):
    return "".join(g[i] if e[i] == "0" else f[i] for i in range(len(e)))

# Function to perform the majority (maj) operation(a,b,c)
def maj(a,b,c):
    return "".join(["0" if sum([int(a[i]),int(b[i]),int(c[i])]) <= 1 else "1" for i in range(32)])

# Function to perform sigma operations when computing t values in compression function.  There is no shifting 
# of the binary in this version of the sigma function, so this has been omitted from this function.  Also there is an
# additional rotation, which has been added to this function's parameters.
def sigmaFinalCompute(bin, rRot1, rRot2, rRot3):
    return "".join(str(i%2) for i in [int(rRot1[i]) + int(rRot2[i]) + int(rRot3[i]) for i in range(len(bin))])

# Main function in which the password is hashed
def get_sha256_hash(txt):

    # Pre-processing (padding of txt) begin here.  
    w = [i for i in padding(txt)]
    
    # Convert the h constants into their corresponding 32 bit binary form.  Each element will be labelled a...h.
    hB = [hexToBin(i) for i in h]

    # Produce the remaining 48  entries of w[16 ... 63]
    for i in range(len(w)):
        for j in range(16,64):
            wa = sigmaFinal(w[i][j-2], 10, sigmaShift(w[i][j-2],17), sigmaShift(w[i][j-2],19))
            wb = w[i][j-7]
            wc = sigmaFinal(w[i][j-15], 3, sigmaShift(w[i][j-15],7), sigmaShift(w[i][j-15],18))
            wd = w[i][j-16]
            w[i].append(addBin(wa,wb,wc,wd))

        # Compute the t values.  Beginning of the compression function using the values stored in our message schedule (w)
        # and the values stored in h(converted to binary in hBin) and values in k.

        # New computed t values stored in this variable.
        finalVals = []

        # Enter loop  for the compression of each message block
        for t in range(64):
            # For the first loop initial h constants(converted from their hexadecimal format to their binary format) are used.
            if t == 0:
                # Compute t1 and t2 values which are used to produce new "a" and "e" values in each loop
                t1 = addBin(hB[7],sigmaFinalCompute(hB[4],sigmaShift(hB[4],6),sigmaShift(hB[4],11),sigmaShift(hB[4],25)),ch(hB[4],hB[5],hB[6]),hexToBin(k[t]),w[i][t])
                t2 = addBin(sigmaFinalCompute(hB[0],sigmaShift(hB[0],2),sigmaShift(hB[0],13),sigmaShift(hB[0],22)),maj(hB[0],hB[1],hB[2]))

                # u ("updated") contains the updated values for "a" and "e" generated from t1 and t2 in forthcoming t loop.
                u = [addBin(t1,t2), addBin(hB[3],t1)]

                # Computing values a ... h1
                h1 = hB[6]
                g = hB[5]
                f = hB[4]
                d = hB[2]
                c = hB[1]
                b = hB[0]
                a = u[0]
                e = u[1]

            else:
                t1 = addBin(h1 ,sigmaFinalCompute(e,sigmaShift(e,6),sigmaShift(e,11),sigmaShift(e,25)), ch(e,f,g),hexToBin(k[t]),w[i][t])
                t2 = addBin(sigmaFinalCompute(a,sigmaShift(a,2),sigmaShift(a,13),sigmaShift(a,22)),maj(a,b,c))

                u = [addBin(t1,t2), addBin(d,t1)]
                
                h1 = g
                g = f
                f = e
                d = c
                c = b
                b = a
                a = u[0]
                e = u[1]

        # Append finalVals with the values a ... h1    
        finalVals.append([a,b,c,d,e,f,g,h1])
        # Generate new hB values
        hB = [addBin(hB[i],finalVals[-1][i]) for i in range(8)]
    # Generate the final hashed hexadecimal message
    return "".join(binToHex(i) for i in hB)     
    
# print(get_sha256_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
# print(get_sha256_hash("password123")) # ➞ "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
# print(get_sha256_hash("Fluffy@home")) # ➞ "dcc1ac3a7148a2d9f47b7dbe3d733040c335b2a3d8adc7984e0c483c5b2c1665"
# print(get_sha256_hash("Hey dude!")) # ➞ "14f997f08b8ad032dcb274198684f995d34043f9da00acd904dc72836359ae0f"
# print(get_sha256_hash("abc"))
# print(get_sha256_hash("a" * 1000000))






