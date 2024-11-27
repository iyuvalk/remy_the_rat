#!/usr/bin/python3
import base64
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys


def load_private_key(pem_file):
    with open(pem_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key


def decrypt_with_private_key(private_key, ciphertext):
    ciphertext_json = json.loads(base64.b64decode(ciphertext))
    encrypted_key = base64.b64decode(ciphertext_json["key"])
    encrypted_iv = base64.b64decode(ciphertext_json["iv"])
    ciphertext_bytes = base64.b64decode(ciphertext_json["ciphertext"])

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_iv = private_key.decrypt(
        encrypted_iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext_bytes)

    return plaintext


def main():
    if len(sys.argv) != 3:
        print("ERROR: Not enough/Too many arguments. Usage: " + sys.argv[
            0] + " <encrypted_file> <private_decryption_key_pem>")
        exit(9)
    commands_filename = sys.argv[1]
    with open(commands_filename) as commands_file:
        encrypted_commands_list = commands_file.read()
    private_key = load_private_key(sys.argv[2])
    decrypted_commands_list = decrypt_with_private_key(private_key=private_key, ciphertext=encrypted_commands_list)
    print(json.dumps(json.loads(decrypted_commands_list), indent=2))


main()