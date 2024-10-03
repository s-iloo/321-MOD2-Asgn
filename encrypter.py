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
        with open(file_path, 'r') as file:
            content = file.read()
            print(f" content is {content}")
    except FileNotFoundError:
        print(f"Error: file not found {file_path}")

    # TODO handle header size (54 bytes)
    encode_text(content, file_path, mode)


# general purpose function that takes an encryption mode and
# runs corresponding encryption algo
def encode_text(content, file_path, encryption_mode):
    if encryption_mode == EncryptionMode.ECB:
        encode_text_ecb(content, file_path)
    elif encryption_mode == EncryptionMode.CBC:
        encode_text_cbc(content, file_path)
    else:
        print(f"unrecognized encryption mode: {encryption_mode}")


def encode_text_ecb(content, file_path):
    # create a 128-bit (16-byte) key
    key = secrets.token_bytes(16)
    print(f"key is {key.hex()}")

    # split the plain text content into 128 bit blocks
    file_size = os.stat(file_path).st_size
    # TODO what are we using this for?
    bytes_to_pad = (16 - file_size) / 8
    print(f"file size is {file_size}")

    # padding is in whole bytes, the value of each added byte is the
    # number of bytes that are added, i.e. N bytes, each of value N are added
    if file_size % 16 != 0:
        content = pad(content.encode('utf-8'), 16, 'pkcs7')
        print(f"padded content is {content}")

    # init the cipher using key, and init the byte array to hold encrypted content
    # each block encrypted separately with the same key
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_byte_array = b""

    # loop through 128 bits (16 bytes) at a time and
    # encrypt each 128 bit block with the generated key
    for i in range(0, len(content), 16):
        # TODO calculate block
        block = 0
        # TODO encrypt call not working bc of block
        encrypted_byte_array += ecb_cipher.encrypt(block)

    # TODO want to write the encrypted data to a binary file
    # should we prompt the user for a file name?
    # either:
    # 1) prompt
    # 2) write to same exact file every time (idk about this)
    # 3) generate file name (kinda interesting)


def encode_text_cbc(content, file_path):
    return
    # TODO cbc


def handle_mode_input():
    while True:
        mode = input("Select an encryption algorithm from specified options:\nECB - Electronic Codebook Mode\n"
                     "CBC - Cipher Block Chaining Mode\n---------------------------------\n[ECB] or [CBC]: ").upper()
        if mode == "ECB":
            print("ECB selected, running encryption...")
            return EncryptionMode.ECB
        elif mode == "ECB":
            print("ECB selected, running encryption...")
            return EncryptionMode.ECB
        print("Received input is invalid. Try again.")


if __name__ == "__main__":
    # should we validate file names? (I think I'm probably thinking to hard about thinhgs)
    file = input("Enter file name: ")
    # we can let users input what encryption they want to use... (or not if I'm missing something)
    encryption_mode = handle_mode_input()
    read_text(file, encryption_mode)
