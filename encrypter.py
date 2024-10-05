from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from enum import Enum
import secrets
import os


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
        return encode_text_cbc(content, file_path)
    else:
        print(f"unrecognized encryption mode: {encryption_mode}")


def add_padding(content, file_size):
    if (file_size - 54) % 16 != 0:
        padding_size = 16 - ((file_size - 54) % 16)
        print("padding_size: ", padding_size)
        padding = bytes([padding_size] * padding_size)
        # print(content + padding)
        return content + padding

    return content
        # Calculate padding size
    # padding_size = 16 - ((file_size - 54) % 16)
    # print("padding_size: ", padding_size)

    # # Create padding (PKCS7-style padding: each byte is the size of the padding)
    # padding = bytes([padding_size] * padding_size)

    # # Return content with padding appended
    # return content + padding

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
    


def encode_text_cbc(content, file_path):
    # generate the iv and key
    iv = secrets.token_bytes(16)
    key = secrets.token_bytes(16)
    print("Generated IV for CBC: ", iv.hex())

    # find the file size in bytes
    file_size = os.stat(file_path).st_size

    encrypted_byte_array = b""
    # generate the cipher
    cbc_cipher = AES.new(key, AES.MODE_CBC)
    # add padding to plaintext
    print("len of content ", len(content))
    content = add_padding(content, file_size)
    # XOR first plaintext block with IV
    xor_operand = iv

    for i in range(54, len(content), 16):
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
