import argparse
import base64
import getpass
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a secret key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(input_path: str, output_path: str, password: str):
    """Encrypt the input file and write the encrypted data to output file."""
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)

    # Save salt + encrypted data to output file
    with open(output_path, "wb") as f:
        f.write(salt + encrypted)
    print(f"File encrypted and saved to {output_path}")

def decrypt_file(input_path: str, output_path: str, password: str):
    """Decrypt the input file and write the decrypted data to output file."""
    with open(input_path, "rb") as f:
        file_data = f.read()

    salt = file_data[:16]
    encrypted = file_data[16:]
    key = derive_key(password.encode(), salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        print("Invalid password or corrupted file.")
        return

    with open(output_path, "wb") as f:
        f.write(decrypted)
    print(f"File decrypted and saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using a password.")
    parser.add_argument("file", help="Path to the input file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the file")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the file")
    parser.add_argument("-o", "--output", help="Output file path (optional)")

    args = parser.parse_args()

    password = getpass.getpass("Enter password: ")

    input_path = args.file
    output_path = args.output
    if not output_path:
        if args.encrypt:
            output_path = input_path + ".encrypted"
        else:
            if input_path.endswith(".encrypted"):
                output_path = input_path.rsplit(".encrypted", 1)[0] + ".decrypted"
            else:
                output_path = input_path + ".decrypted"

    if args.encrypt:
        encrypt_file(input_path, output_path, password)
    else:
        decrypt_file(input_path, output_path, password)

if __name__ == "__main__":
    main()
