# AES Encryption and Decryption Project

This project follows the supplied `Project_AES.pdf` brief.

## What is included

1. `aes_core.py` — educational AES-128 implementation in pure Python:
   - `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key`
   - inverse transformations for decryption
   - AES-128 key expansion, encryption, and decryption of one 16-byte block
2. `secure_file_app.py` — practical file/text encryption using AES-GCM from the
   established `cryptography` library and a password-derived key.
3. `experiments.py` — round-trip and avalanche-effect experiments.
4. `tests/` — automated tests.

**Safety note:** `aes_core.py` is for learning and coursework, not for protecting real
sensitive data. The practical application uses AES-GCM, which also detects tampering.

## Requirements

- Python 3.10 or newer recommended
- For the practical app only: `cryptography`

## Windows setup (PowerShell)

Open PowerShell in this project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

## Step 1 — run the AES block demonstration

```powershell
python aes_core.py
```

The demo uses a standard AES-128 test vector. Expected ciphertext:

`69c4e0d86a7b0430d8cdb78070b4c55a`

The output should also show that decryption returns the original block.

## Step 2 — run the experiments

```powershell
python experiments.py
```

This checks:
- decrypt(encrypt(plaintext)) equals the original plaintext
- how many ciphertext bits change when one plaintext bit changes
- how many ciphertext bits change when one key bit changes

The avalanche effect is statistical: for a 128-bit block, a well-behaved cipher
typically changes about half the ciphertext bits after a one-bit input change.
One run does not have to produce exactly 64 changed bits.

## Step 3 — encrypt and decrypt a file

Encrypt:

```powershell
python secure_file_app.py encrypt sample.txt sample.enc
```

Decrypt:

```powershell
python secure_file_app.py decrypt sample.enc recovered.txt
```

The program asks for a password. Use the same password to decrypt. The output file
is written only after authentication succeeds.

Create a sample file first:

```powershell
Set-Content sample.txt "This is a confidential test message."
```

## Step 4 — use the text mode

```powershell
python secure_file_app.py text
```

Choose encrypt or decrypt from the menu. The encrypted output is Base64 so it can
be copied as text.

## How the code works

### Educational AES-128 core
- AES uses a 16-byte block and a 16-byte key.
- The key schedule expands the original key into 11 round keys.
- Initial step: `AddRoundKey`.
- Rounds 1–9: `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`.
- Final round: `SubBytes`, `ShiftRows`, `AddRoundKey` (no `MixColumns`).
- Decryption reverses the transformations in the opposite order.

### Practical app
- A random salt is generated for password-based key derivation.
- PBKDF2-HMAC-SHA256 derives a 256-bit key from the password and salt.
- AES-GCM uses a fresh random 12-byte nonce and authenticates the ciphertext.
- The file format stores a version marker, salt, nonce, and encrypted data.
- If the password is wrong or the file was changed, authentication fails.

