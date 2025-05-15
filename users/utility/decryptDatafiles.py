import os
import hashlib
import logging
from cryptography.fernet import Fernet
from django.conf import settings

import base64
import hashlib


def str_to_fernet_key(input_str):
    # Convert the input string to bytes
    input_bytes = input_str.encode('utf-8')

    # Hash the bytes using SHA-256 (32 bytes)
    hash_bytes = hashlib.sha256(input_bytes).digest()

    # Base64-encode the hash to make it URL-safe
    fernet_key = base64.urlsafe_b64encode(hash_bytes)

    # Return the 32-byte key (Fernet keys are 32 bytes)
    return fernet_key[:32]


# Step 4: Decrypt Data (for authorized users)
def decrypt_data(encrypted_data, key):
    # key = open("encryption_key.key", "rb").read()
    print(type(key))
    print(key)
    key = key.encode('utf-8') #str_to_fernet_key(key)
    print(type(key))
    print(key)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data


# Step 9: Main Security Pipeline
def main_security_pipeline(filepath, key):
    path = os.path.join(settings.MEDIA_ROOT, 'actual', filepath)
    file1 = open(path, "r+")
    # Encryption & Decryption Demonstration (Confidentiality Control)
    cipherData = file1.read()  # "This is some highly sensitive information."

    print("\n--- Decrypting Sensitive Data ---")
    decrypted = decrypt_data(cipherData, key)
    print(f"Decrypted Data: {decrypted}")
    return decrypted


# Execute the security pipeline
def star_process(filepath, key):
    return main_security_pipeline(filepath, key)
