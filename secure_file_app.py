"""Practical text/file encryption using password-derived AES-GCM keys.

This is separate from the educational AES implementation. AES-GCM provides
confidentiality and detects modifications to encrypted data.
"""
import base64
import getpass
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"AESDEMO1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
ITERATIONS = 600_000

def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC)
    return MAGIC + salt + nonce + ciphertext

def decrypt_bytes(blob: bytes, password: str) -> bytes:
    minimum = len(MAGIC) + SALT_LEN + NONCE_LEN + 16
    if len(blob) < minimum or not blob.startswith(MAGIC):
        raise ValueError("Not a valid AES demo file or the file is incomplete.")
    pos = len(MAGIC)
    salt = blob[pos:pos+SALT_LEN]
    pos += SALT_LEN
    nonce = blob[pos:pos+NONCE_LEN]
    pos += NONCE_LEN
    ciphertext = blob[pos:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, MAGIC)

def encrypt_file(source, destination):
    password = getpass.getpass("Choose encryption password: ")
    data = Path(source).read_bytes()
    Path(destination).write_bytes(encrypt_bytes(data, password))
    print(f"Encrypted {source} -> {destination}")

def decrypt_file(source, destination):
    password = getpass.getpass("Enter decryption password: ")
    try:
        data = decrypt_bytes(Path(source).read_bytes(), password)
    except Exception as exc:
        print(f"Decryption failed: {exc}")
        print("Check the password and ensure the encrypted file was not modified.")
        raise SystemExit(1)
    Path(destination).write_bytes(data)
    print(f"Decrypted {source} -> {destination}")

def text_mode():
    print("1) Encrypt text")
    print("2) Decrypt Base64 text")
    choice = input("Choose 1 or 2: ").strip()
    if choice == "1":
        message = input("Text to encrypt: ")
        password = getpass.getpass("Password: ")
        encoded = base64.b64encode(encrypt_bytes(message.encode("utf-8"), password)).decode("ascii")
        print("\nEncrypted Base64:\n" + encoded)
    elif choice == "2":
        encoded = input("Paste encrypted Base64: ").strip()
        password = getpass.getpass("Password: ")
        try:
            blob = base64.b64decode(encoded, validate=True)
            message = decrypt_bytes(blob, password).decode("utf-8")
            print("\nDecrypted text:\n" + message)
        except Exception:
            print("Could not decrypt. Check the password and the pasted text.")
            raise SystemExit(1)
    else:
        print("Please choose 1 or 2.")

def main():
    if len(sys.argv) == 2 and sys.argv[1].lower() == "text":
        text_mode()
    elif len(sys.argv) == 4 and sys.argv[1].lower() == "encrypt":
        encrypt_file(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1].lower() == "decrypt":
        decrypt_file(sys.argv[2], sys.argv[3])
    else:
        print("Usage:")
        print("  python secure_file_app.py encrypt input_file output_file")
        print("  python secure_file_app.py decrypt input_file output_file")
        print("  python secure_file_app.py text")

if __name__ == "__main__":
    main()
