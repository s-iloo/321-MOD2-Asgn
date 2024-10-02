from Crypto.Util.Padding import pad
import secrets
import os


def read_text(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            print(content)
    except FileNotFoundError:
        print(f"Error: file not found {file_path}")
    
    encode_text(content, file_path)
    

def encode_text(content, file_path):
    #each block encrypted separately with the same key

    # create a 128 bit key
    key = secrets.token_bytes(128)
    print(key)

    # split the plain text content into 128 bit blocks
    file_size = os.stat(file_path).st_size
    bytes_to_pad = (128 - file_size) /  8
    print(file_size)

    # padding is in whole bytes, the value of each added byte is the
    # number of bytes that are added, i.e. N bytes, each of value N are added
    if file_size % 128 != 0:
        content = pad(content.encode('utf-8'), 128, 'pkcs7')
        print(content)

    # now i need to loop through 128 bits at a time and encrypt each 128 bit block
    # with the generated key
    




if __name__ == "__main__":
    file = input("Enter file name: ")
    read_text(file)


