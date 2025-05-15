import os
import hashlib
import logging
from cryptography.fernet import Fernet
from django.conf import settings


# Step 1: Generate and Store Encryption Key (for confidentiality)
def generate_encryption_key():
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)
    print("Encryption key generated and stored securely.")
    return key


# Step 2: Load the Encryption Key
def load_encryption_key():
    return open("encryption_key.key", "rb").read()


# Step 3: Encrypt Sensitive Data (Confidentiality control, NIST 3.13.8 & ISO 27002 A.10.1.1)
def encrypt_data(data):
    key = load_encryption_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data


# Step 4: Decrypt Data (for authorized users)
def decrypt_data(encrypted_data):
    key = load_encryption_key()
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data


# Step 5: Implement Access Control (NIST 3.1.1 & ISO 27002 A.9.1.2)
def access_control(username, password):
    # Simulating a user database
    users_db = {"admin": "admin123", "user1": "password1"}

    # if username in users_db and users_db[username] == password:
    if username == 'admin' and password == 'admin':
        print(f"Access granted for {username}.")
        return True
    else:
        print("Access denied.")
        return False


# Step 6: Implement Logging (Audit control - NIST 3.3.5 & ISO 27002 A.12.4.1)
def setup_logging():
    logging.basicConfig(filename="security_audit.log", level=logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s")
    logging.info("Security audit started.")


# Step 7: Log Security Events
def log_event(event):
    logging.info(event)


# Step 8: Implement Integrity Check using Hashing (NIST 3.14.1 & ISO 27002 A.12.2.1)
def check_file_integrity(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# Step 9: Main Security Pipeline
def main_security_pipeline(filepath):
    setup_logging()
    path = os.path.join(settings.MEDIA_ROOT, 'actual', filepath)
    file1 = open(path, "r+")
    # Encryption & Decryption Demonstration (Confidentiality Control)
    sensitive_data = file1.read()  # "This is some highly sensitive information."
    print("\n--- Encrypting Sensitive Data ---")
    encrypted = encrypt_data(sensitive_data)
    with open(path, "w") as f:
        f.write(encrypted.decode())
    print(f"Encrypted Data: {encrypted}")

    # print("\n--- Decrypting Sensitive Data ---")
    # decrypted = decrypt_data(encrypted)
    # print(f"Decrypted Data: {decrypted}")
    return encrypted
    # # Access Control Simulation
    # print("\n--- Simulating Access Control ---")
    # username = input("Enter your username: ")
    # password = input("Enter your Password: ")  # getpass("Enter your password: ")
    #
    # if access_control(username, password):
    #     log_event(f"User {username} logged in successfully.")
    # else:
    #     log_event(f"Unauthorized access attempt by {username}.")
    #
    # # File Integrity Check
    # print("\n--- Checking File Integrity ---")
    # test_file = "test_file.txt"
    # # with open(test_file, "w") as f:
    # # f.write("Important data.")
    #
    # original_hash = check_file_integrity(test_file)
    # print(f"Original file hash: {original_hash}")
    #
    # # Simulate file tampering
    # # with open(test_file, "a") as f:
    # # f.write("Malicious tampering.")
    #
    # tampered_hash = check_file_integrity(test_file)
    # print(f"Tampered file hash: {tampered_hash}")
    #
    # if original_hash != tampered_hash:
    #     log_event(f"File {test_file} integrity check failed! Possible tampering detected.")
    #     print("Integrity check failed. File may have been tampered with.")
    # else:
    #     log_event(f"File {test_file} passed integrity check.")
    #     print("File integrity is intact.")


# Execute the security pipeline
def star_process(filepath):
    # Generate encryption key if not already generated
    key = None
    # if not os.path.exists("encryption_key.key"):
    key = generate_encryption_key()
    print("Key is:", key)

    return key, main_security_pipeline(filepath)
