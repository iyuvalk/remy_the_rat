#!/usr/bin/python3
import base64
import json
import os.path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys



def load_public_key(pem_file):
    with open(pem_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def encrypt_with_public_key(public_key, plaintext):
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_iv = public_key.encrypt(
        iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    result = {
        "key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(encrypted_iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    return base64.b64encode(json.dumps(result).encode()).decode()


def main():
    if len(sys.argv) != 3:
        print("ERROR: Not enough/Too many arguments. Usage: " + sys.argv[
            0] + " <file> <public_encryption_key_pem>")
        exit(9)
    commands_filename = sys.argv[1]
    with open(commands_filename) as commands_file:
        commands_list = commands_file.read()
    public_key = load_public_key(sys.argv[2])
    encrypted_commands_list = encrypt_with_public_key(public_key=public_key, plaintext=commands_list)
    with open(os.path.splitext(commands_filename)[0], "w") as commands_file_enc:
        commands_file_enc.write(encrypted_commands_list)
    print("Done.")


main()