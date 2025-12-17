# Secure File Encryptor 

## Overview
Secure File Encryptor is a Python-based tool that allows users to
encrypt and decrypt files using password-based encryption.

It uses industry-standard cryptographic techniques instead of
custom or insecure encryption logic.

---

## Features
- Password-based file encryption
- AES-backed encryption using Fernet
- Secure key derivation using PBKDF2
- No password or key stored on disk
- Simple command-line interface

---

## Technologies Used
- Python 3
- cryptography library
- PBKDF2 with SHA256
- Fernet (AES encryption)

---

## Installation

1. Clone the repository:
  git clone 

2. Navigate into the project folder: 
  cd Secure-File-Encryptor 

3. Install dependencies:
  pip install -r requirements.txt

---

## Usage

Run the script:
 python secure_file_encryptor.py

### Encrypt a file

Encrypt or Decrypt (e/d): e
Enter file path: example.txt
Enter password: ********

### Decrypt a file

Encrypt or Decrypt (e/d): d
Enter file path: example.txt.enc
Enter password: ********

---

## Important Notes
- Decryption will fail if the password is incorrect.
- Each encrypted file uses a random salt for improved security.
- This project is intended for educational and ethical use only.

---

## Learning Outcomes
- Understanding password-based encryption
- Secure key derivation using PBKDF2
- Proper use of cryptographic libraries
- Avoiding insecure custom encryption methods

---

## Credits
Rohit Verma -- Made for GKV cybersecurity.