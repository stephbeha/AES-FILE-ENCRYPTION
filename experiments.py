"""Run round-trip and one-bit avalanche experiments for the educational AES core."""
from aes_core import encrypt_block, decrypt_block

def hamming_distance(a, b):
    """Count how many individual bits differ between two byte strings."""
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def flip_first_bit(data):
    return bytes([data[0] ^ 0x01]) + data[1:]

def main():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    cipher = encrypt_block(plaintext, key)
    recovered = decrypt_block(cipher, key)

    changed_plaintext_cipher = encrypt_block(flip_first_bit(plaintext), key)
    changed_key_cipher = encrypt_block(plaintext, flip_first_bit(key))

    print("AES EXPERIMENTS")
    print("-" * 48)
    print("Original plaintext :", plaintext.hex())
    print("Ciphertext          :", cipher.hex())
    print("Decrypted plaintext :", recovered.hex())
    print("Round-trip correct  :", recovered == plaintext)
    print()
    print("Change one plaintext bit:")
    print("  Changed ciphertext:", changed_plaintext_cipher.hex())
    print("  Cipher bits changed:", hamming_distance(cipher, changed_plaintext_cipher), "/ 128")
    print()
    print("Change one key bit:")
    print("  Changed ciphertext:", changed_key_cipher.hex())
    print("  Cipher bits changed:", hamming_distance(cipher, changed_key_cipher), "/ 128")

if __name__ == "__main__":
    main()
