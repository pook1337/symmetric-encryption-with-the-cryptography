
# symmetric-encryption-with-the-cryptography

A simple Python project demonstrating how to perform symmetric encryption and decryption using the [cryptography](https://cryptography.io/en/latest/) library. This repository provides example code to securely encrypt and decrypt data or files with a password-derived key.

---

## Features

- Symmetric encryption using AES (via Fernet)  
- Password-based key derivation with PBKDF2HMAC and SHA256  
- Secure random salt generation  
- Easy-to-use functions for encrypting and decrypting files or data  
- Command-line interface example included  

---

## Requirements

- Python 3.6+  
- [`cryptography`](https://pypi.org/project/cryptography/) library  

---

## Installation

Clone the repository:

```
git clone https://github.com/pook1337/symmetric-encryption-with-the-cryptography.git
cd symmetric-encryption-with-the-cryptography
```

Install dependencies:

```
pip install cryptography
```

---

## Usage

The main script (`es.py`) contains functions to:

- Derive a secure encryption key from a password and salt  
- Encrypt data or files  
- Decrypt data or files  

### Example: Encrypt a file

```
from es import encrypt_file

password = "your_password"
encrypt_file("plain.txt", "encrypted.bin", password)
```

### Example: Decrypt a file

```
from es import decrypt_file

password = "your_password"
decrypt_file("encrypted.bin", "decrypted.txt", password)
```

---

## How It Works

- A random 16-byte salt is generated for each encryption to ensure unique keys.  
- The password and salt are used to derive a 32-byte key using PBKDF2HMAC with SHA256.  
- The derived key is used with Fernet (AES in CBC mode with HMAC) to encrypt or decrypt the data.  
- The salt is prepended to the encrypted file to allow key derivation during decryption.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

