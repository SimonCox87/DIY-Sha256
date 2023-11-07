from sha256 import get_sha256_hash

# variable recording the amount of incorrect file names input by the user.
attempts = 0

# Enter the while loop prompting the user for the file to encrypt.
while True:
    # Enter the try block - user attempts to enter the file name for the file which they wish to hash
    try:
        # User prompted for file name.
        file = input("Enter file name: ")
        # Open the file to read in binary mode and then decode this, so that the message can be processed by the
        # get_sha256_hash function.
        with open(file,"rb") as data:
            hash = get_sha256_hash(data.read().decode("LATIN-1"))
    # exception if the file is not found.
    except FileNotFoundError:
        print(f'Sorry "{file}" doesn\'t exist! Please try again: \n')
    # if the file is found print the hash
    else:
        print(hash)
        break
    # if the user enters an incorrect file name add +1 to attempts counter 
    finally:
        attempts += 1
        # if number of incorrect attempts entered is 3 print the below message.
        if attempts == 3:
            print("Wrong file name entered three times!\nPlease check the file name and try again.")
            break


#Use imported hashlib module to test the above program
import hashlib

with open(file,"rb") as f:
    bytes = f.read()
    readable_hash = hashlib.sha256(bytes).hexdigest()
    print(readable_hash)