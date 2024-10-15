from enum import Enum


# enum to represent our different encryption modes
class EncryptionMode(Enum):
    ECB = 1
    CBC = 2


# function that adds padding when a file's content isn't equally dividable into chunks of 16 bytes
def add_padding(content, file_size, starting=54):
    if (file_size - starting) % 16 != 0:
        padding_size = 16 - ((file_size - starting) % 16)
        print("padding_size: ", padding_size)
        padding = bytes([padding_size] * padding_size)
        return content + padding

    return content


# padding remover based on how we pad in add_padding
def remove_padding(padded_data):
    # the last byte indicates the padding length
    padding_len = padded_data[-1]
    if len(set(padded_data[-padding_len:])) == 1:
        return padded_data[:-padding_len]
    return padded_data


# given a byte array, prints out the bits that make up said array
def print_bits_from_byte_array(barray):
    for byte in barray:
        for i in range(0, 8):
            if byte:
                print(f"{byte & 1}", end="")
            else:
                print("0", end="")
            byte >>= 1
    print("")


# prompting the user for file name, writing encrypted data to said file
# note that files that require padding may not be open-able in original format
def write_to_file(content):
    file_name = input("Enter file to write encrypted data: ")
    with open("output/" + file_name, "wb") as f:
        f.write(content)
    print(f"Content has been written to file output/{file_name}")
    f.close()

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


# given ciphertext, modifies it such that the decrypted plaintext contains the target string
def bit_flip_attack(ciphertext):
    # string we want to inject into the plaintext
    ciphertext = bytearray(ciphertext)
    bit = ord('.') ^ ord('=')
    bit2 = ord('=') ^ ord(';')

    # flipping period to equal sign
    ciphertext[9] = ciphertext[9] ^ bit
    # flipping equal sign to semicolon
    ciphertext[3] = ciphertext[3] ^ bit2
    return bytes(ciphertext)
