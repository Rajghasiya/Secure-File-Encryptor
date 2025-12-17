import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from getpass import getpass

def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path):
    password = getpass("Enter password: ")
    salt = os.urandom(16)

    key = generate_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    with open(file_path + ".enc", "wb") as f:
        f.write(salt + encrypted)

    print("File encrypted successfully")

def decrypt_file(file_path):
    password = getpass("Enter password: ")

    with open(file_path, "rb") as f:
        salt = f.read(16)
        encrypted = f.read()

    key = generate_key(password, salt)
    fernet = Fernet(key)

    decrypted = fernet.decrypt(encrypted)

    output_file = file_path.replace(".enc", "")
    with open(output_file, "wb") as f:
        f.write(decrypted)

    print("File decrypted successfully")

if __name__ == "__main__":
    choice = input("Encrypt or Decrypt (e/d): ").lower()
    path = input("Enter file path: ")

    if choice == "e":
        encrypt_file(path)
    elif choice == "d":
        decrypt_file(path)
    else:
        print("Invalid option")
        