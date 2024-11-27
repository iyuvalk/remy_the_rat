#!/usr/bin/python3

from Crypto.PublicKey import RSA

# Generate RSA key pair
key = RSA.generate(2048)

# Export the private key in PEM format
private_key = key.export_key()
with open('private.pem', 'wb') as f:
    f.write(private_key)

# Export the public key in PEM format
public_key = key.publickey().export_key()
with open('public.pem', 'wb') as f:
    f.write(public_key)

print("RSA key pair generated and saved as 'private.pem' and 'public.pem'.")
