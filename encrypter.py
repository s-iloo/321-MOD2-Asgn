from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from enum import Enum
import secrets
import os
from urllib.parse import quote

prepend = "userid=456;userdata="
append = ";session-id=31337"

# enum to represent our different encryption modes
class EncryptionMode(Enum):
    ECB = 1
    CBC = 2


def read_text(file_path, mode):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            print(f"content is \n{content}\n")
    except FileNotFoundError:
        print(f"Error: file not found {file_path}")

    # TODO handle header size (54 bytes). We are encrypting .bmp files, not .txt files
    encode_text(content, file_path, mode)


# general purpose function that takes an encryption mode and
# runs corresponding encryption algo
def encode_text(content, file_path, encryption_mode):
    if encryption_mode == EncryptionMode.ECB:
        return encode_text_ecb(content, file_path)
    elif encryption_mode == EncryptionMode.CBC:
        return encode_text_cbc(content, file_path = file_path)
    else:
        print(f"unrecognized encryption mode: {encryption_mode}")


def add_padding(content, file_size, starting = 54):
    if (file_size - starting) % 16 != 0:
        padding_size = 16 - ((file_size - starting) % 16)
        print("padding_size: ", padding_size)
        padding = bytes([padding_size] * padding_size)
        # print(content + padding)
        return content + padding

    return content

def encode_text_ecb(content, file_path):
    # create a 128-bit (16-byte) key
    key = secrets.token_bytes(16)
    print(f"key is {key.hex()}")

    # split the plain text content into 128 bit blocks
    file_size = os.stat(file_path).st_size
    print(f"file size is {file_size}")

    # padding is in whole bytes, the value of each added byte is the
    # number of bytes that are added, i.e. N bytes, each of value N are added
    # if file_size % 16 != 0:

    #     print(f"padded content is {content.hex()}")
    content = add_padding(content, file_size)
    print("content size is: ", len(content[54:]))
    # TODO xor content?

    # init the cipher using key, and init the byte array to hold encrypted content
    # each block encrypted separately with the same key
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_byte_array = b""

    header = content[0:54]
    print("len of header ", len(header))

    # loop through 128 bits (16 bytes) at a time and
    # encrypt each 128 bit block with the generated key
    for i in range(54, len(content), 16):
        # print("i is ", i)
        block = content[i:i + 16]
        # print("len of block is ", len(block))
        encrypted_byte_array += ecb_cipher.encrypt(block)

    encrypted_byte_array = header + encrypted_byte_array
    print(f"encrypted byte array is {encrypted_byte_array.hex()}")

    print("bits are ", end="")
    print_bits_from_byte_array(encrypted_byte_array)

    print(f"DECRYPTOED: {ecb_cipher.decrypt(encrypted_byte_array[54:])}")

    write_to_file(encrypted_byte_array)
    return encrypted_byte_array


# TODO want to write the encrypted data to a binary file (as another function)
# should we prompt the user for a file name?
# either:
# 1) prompt
# 2) write to same exact file every time (idk about this)
# 3) generate file name (kinda interesting)
def write_to_file(content):
    file = input("Enter file to write encrypted data: ")
    with open(file, "wb") as file:
        file.write(content)
    


def encode_text_cbc(content, file_path = None, given_key = None, given_iv = None, starting = None):
    # generate the iv and key
    if given_key is None  and given_iv is None:
        iv = secrets.token_bytes(16)
        key = secrets.token_bytes(16)
    else:
        iv = given_iv
        key = given_key

    print("Generated IV for CBC: ", iv.hex())

    # find the file size in bytes
    if file_path is not None:
        file_size = os.stat(file_path).st_size
    else:
        file_size = len(content)
    
    if starting is None:
        starting = 54


    encrypted_byte_array = b""
    # generate the cipher
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    # add padding to plaintext
    print("len of content ", len(content))
    content = add_padding(content, file_size, starting)
    # XOR first plaintext block with IV
    xor_operand = iv

    for i in range(starting, len(content), 16):
        # convert the bytes to ints for xor
        int1 = int.from_bytes(content[i:i+16], 'big')
        int2 = int.from_bytes(xor_operand, 'big')
        # xor
        xor_output = int1 ^ int2
        # convert the xor_output back to 16 byte block
        xor_output = xor_output.to_bytes(16, 'big')
        # encrypt
        cipher_text = cbc_cipher.encrypt(xor_output)
        encrypted_byte_array += cipher_text
        # set the next xor_operand to the generated cipher text
        xor_operand = cipher_text

    write_to_file(encrypted_byte_array)
    print(encrypted_byte_array)
    return encrypted_byte_array


def print_bits_from_byte_array(barray):
    for byte in barray:
        for i in range(0, 8):
            if byte:
                print(f"{byte & 1}", end="")
            else:
                print("0", end="")
            byte >>= 1
    print("\n")

def submit(string, key, iv):
    string = quote(string)
    new_string = prepend + string + append
    print(new_string)

    encrypt = encode_text_cbc(new_string.encode("utf-8"), given_key = key, given_iv = iv, starting = 0)

    return encrypt

def cbc_decrypt(ciphertext, key, iv):
    # the first xor_operand is the iv
    xor_operand = iv
    # generate the cbc_cipher with the key and the iv
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_array = b""

    # loop through the cipher text 
    for i in range(0, len(ciphertext), 16):
        decrypt_result = cbc_cipher.decrypt(ciphertext[i:i + 16])

        decrypt_result = int.from_bytes(decrypt_result, 'big')
        xor_operand = int.from_bytes(xor_operand, 'big')

        # the xor_output should be the first block of plaintext
        xor_output = xor_operand ^ decrypt_result
        print(xor_output.to_bytes(16, 'big'))
        
        # append the plaintext block 
        plaintext_array += xor_output.to_bytes(16, 'big')

        # set the next xor_operand
        xor_operand = ciphertext[i:i + 16]

    print(plaintext_array)
    return plaintext_array

def verify(string):
    # generating the constant key and iv
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    # getting the encrypted string
    encrypted_string = submit(string, key, iv)

    # decrypting the encrypted string
    decrypted_string = cbc_decrypt(encrypted_string, key, iv)

    if ";admin=true;" in decrypted_string.decode("utf-8"):
        print("Admin is true??")
        return True
    else: 
        return False

def handle_mode_input():
    while True:
        mode = input("Select an encryption algorithm from specified options:\nECB - Electronic Codebook Mode\n"
                     "CBC - Cipher Block Chaining Mode\n---------------------------------\n[ECB] or [CBC]: ").upper()
        if mode == "ECB":
            print("ECB selected, running encryption...")
            return EncryptionMode.ECB
        elif mode == "CBC":
            print("CBC selected, running encryption...")
            return EncryptionMode.CBC
        print("Received input is invalid. Try again.")


if __name__ == "__main__":
    # should we validate file names? (I think I'm probably thinking to hard about thinhgs)
    file = input("Enter file name: ")
    # we can let users input what encryption they want to use... (or not if I'm missing something)
    encryption_mode = handle_mode_input()
    read_text(file, encryption_mode)
    string = input("Enter user provided string: ")
    verify(string)
