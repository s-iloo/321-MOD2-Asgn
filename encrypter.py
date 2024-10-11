from Crypto.Cipher import AES
import secrets
import os
from urllib.parse import quote

from encrypter_util import *

prepend = "userid=456;userdata="
append = ";session-id=31337"


def main():
    file_path = input("Enter relative path to file: ")
    encryption_mode = handle_mode_input()
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: file not found {file_path}")

    encode_text(content, file_path, encryption_mode)

    string = input("Enter user provided string: ")
    verify(string)


# general purpose function that takes an encryption mode and
# runs corresponding encryption algo
def encode_text(content, file_path, encryption_mode):
    if encryption_mode == EncryptionMode.ECB:
        return encode_text_ecb(content, file_path)
    elif encryption_mode == EncryptionMode.CBC:
        return encode_text_cbc(content, file_path=file_path)
    else:
        print(f"unrecognized encryption mode: {encryption_mode}")


def encode_text_ecb(content, file_path):
    # create a 128-bit (16-byte) key
    key = secrets.token_bytes(16)
    print(f"key is {key.hex()}")

    content = add_padding(content, len(content))    

    # init the cipher using key, and init the byte array to hold encrypted content
    # each block encrypted separately with the same key
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_byte_array = b""

    header = content[0:54]

    # loop through 128 bits (16 bytes) at a time and
    # encrypt each 128 bit block with the generated key
    for i in range(54, len(content), 16):
        block = content[i:i + 16]
        encrypted_byte_array += ecb_cipher.encrypt(block)

    encrypted_byte_array = header + encrypted_byte_array
    write_to_file(encrypted_byte_array)
    return encrypted_byte_array


def encode_text_cbc(content, file_path=None, given_key=None, given_iv=None, starting=54):
    # generate the iv and key
    if given_key is None and given_iv is None:
        iv = secrets.token_bytes(16)
        key = secrets.token_bytes(16)
    else:
        iv = given_iv
        key = given_key

    # find the file size in bytes
    if file_path is not None:
        file_size = os.stat(file_path).st_size
    else:
        file_size = len(content)

    encrypted_byte_array = b""
    # generate the cipher
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    # add padding to plaintext
    content = add_padding(content, file_size, starting)

    for i in range(starting, len(content), 16):
        # encrypt 16 bytes at a time
        cipher_text = cbc_cipher.encrypt(content[i:i + 16])
        encrypted_byte_array += cipher_text

    encrypted_byte_array = content[:starting] + encrypted_byte_array
    write_to_file(encrypted_byte_array)
    return encrypted_byte_array


def submit(string, key, iv):
    string = quote(string)
    new_string = prepend + string + append

    encrypt = encode_text_cbc(new_string.encode("utf-8"), given_key=key, given_iv=iv, starting=0)

    return encrypt


def cbc_decrypt(ciphertext, key, iv):
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext
    decrypted_data = remove_padding(cbc_cipher.decrypt(ciphertext))
    return decrypted_data


def verify(string):
    # generating the constant key and iv
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    # getting the encrypted string
    encrypted_string = submit(string, key, iv)

    # attacking the encrypted string
    encrypted_string = bit_flip_attack(encrypted_string)
    
    # decrypting the encrypted string
    decrypted_string = cbc_decrypt(encrypted_string, key, iv)

    if b";admin=true;" in decrypted_string:
        print("Admin is true?? (you've been attacked)")
        return True
    else:
        return False


if __name__ == "__main__":
    main()
