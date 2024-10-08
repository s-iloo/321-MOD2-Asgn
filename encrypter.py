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
            print(f"content is \n{content}\n")
    except FileNotFoundError:
        print(f"Error: file not found {file_path}")

    # TODO handle header size (54 bytes). We are encrypting .bmp files, not .txt files
    encode_text(content, file_path, encryption_mode)

    # idk if we should do it like this but works for now ig
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

    # split the plain text content into 128 bit blocks
    file_size = os.stat(file_path).st_size
    print(f"file size is {file_size}")

    # padding is in whole bytes, the value of each added byte is the
    # number of bytes that are added, i.e. N bytes, each of value N are added

    content = add_padding(content, file_size)
    print("content size is: ", len(content[54:]))

    # init the cipher using key, and init the byte array to hold encrypted content
    # each block encrypted separately with the same key
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_byte_array = b""

    header = content[0:54]
    print("len of header ", len(header))

    # loop through 128 bits (16 bytes) at a time and
    # encrypt each 128 bit block with the generated key
    for i in range(54, len(content), 16):
        block = content[i:i + 16]
        encrypted_byte_array += ecb_cipher.encrypt(block)

    encrypted_byte_array = header + encrypted_byte_array
    print(f"encrypted byte array is {encrypted_byte_array.hex()}")

    print("bits are ", end="")
    print_bits_from_byte_array(encrypted_byte_array)

    print(f"DECRYPTOED: {ecb_cipher.decrypt(encrypted_byte_array[54:])}")

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

    print("Generated IV for CBC: ", iv.hex())

    # find the file size in bytes
    if file_path is not None:
        file_size = os.stat(file_path).st_size
    else:
        file_size = len(content)

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
        int1 = int.from_bytes(content[i:i + 16], 'big')
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

    encrypted_byte_array = content[0:starting] + encrypted_byte_array
    write_to_file(encrypted_byte_array)
    return encrypted_byte_array


def submit(string, key, iv):
    string = quote(string)
    new_string = prepend + string + append
    print(new_string)

    encrypt = encode_text_cbc(new_string.encode("utf-8"), given_key=key, given_iv=iv, starting=0)

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

    # bit flip?
    bit_flip_attack(encrypted_string)

    # decrypting the encrypted string
    decrypted_string = cbc_decrypt(encrypted_string, key, iv)

    print("DECRYPT WORK")
    print(decrypted_string)

    decrypted_string = remove_padding(decrypted_string)

    print(decrypted_string)

    if ";admin=true;" in decrypted_string.decode("utf-8"):
        print("Admin is true??")
        return True
    else:
        return False


if __name__ == "__main__":
    main()
