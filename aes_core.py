"""Educational AES-128 block cipher implementation (pure Python).

For coursework and testing only. Do not use this implementation for real secrets.
AES state is stored in column-major order, as specified by AES.
"""
BLOCK_SIZE = 16

def _gf_mul(a, b):
    """Multiply bytes in GF(2^8), using the AES irreducible polynomial 0x11B."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result

def _gf_pow(a, power):
    result = 1
    while power:
        if power & 1:
            result = _gf_mul(result, a)
        a = _gf_mul(a, a)
        power >>= 1
    return result

def _rotl8(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF

def _make_sboxes():
    sbox, inv = [], [0] * 256
    for x in range(256):
        inverse = 0 if x == 0 else _gf_pow(x, 254)
        y = inverse ^ _rotl8(inverse, 1) ^ _rotl8(inverse, 2) ^ _rotl8(inverse, 3) ^ _rotl8(inverse, 4) ^ 0x63
        sbox.append(y)
        inv[y] = x
    return sbox, inv

SBOX, INV_SBOX = _make_sboxes()

def _to_state(block):
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes.")
    return [[block[4*c + r] for c in range(4)] for r in range(4)]

def _from_state(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))

def sub_bytes(state):
    """Replace every state byte using the AES S-box; returns a new state."""
    return [[SBOX[value] for value in row] for row in state]

def inv_sub_bytes(state):
    return [[INV_SBOX[value] for value in row] for row in state]

def shift_rows(state):
    """Circularly shift row r left by r positions."""
    return [row[r:] + row[:r] for r, row in enumerate(state)]

def inv_shift_rows(state):
    return [row[-r:] + row[:-r] if r else row[:] for r, row in enumerate(state)]

def mix_columns(state):
    """Mix each column using multiplication in GF(2^8)."""
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        out[0][c] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
        out[1][c] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
        out[2][c] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
        out[3][c] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)
    return out

def inv_mix_columns(state):
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        out[0][c] = _gf_mul(a[0],14) ^ _gf_mul(a[1],11) ^ _gf_mul(a[2],13) ^ _gf_mul(a[3],9)
        out[1][c] = _gf_mul(a[0],9) ^ _gf_mul(a[1],14) ^ _gf_mul(a[2],11) ^ _gf_mul(a[3],13)
        out[2][c] = _gf_mul(a[0],13) ^ _gf_mul(a[1],9) ^ _gf_mul(a[2],14) ^ _gf_mul(a[3],11)
        out[3][c] = _gf_mul(a[0],11) ^ _gf_mul(a[1],13) ^ _gf_mul(a[2],9) ^ _gf_mul(a[3],14)
    return out

def add_round_key(state, round_key):
    """XOR state with a 16-byte round key."""
    key_state = _to_state(round_key)
    return [[state[r][c] ^ key_state[r][c] for c in range(4)] for r in range(4)]

def _key_expansion(key):
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes.")
    words = [list(key[i:i+4]) for i in range(0, 16, 4)]
    rcon = 1
    while len(words) < 44:
        temp = words[-1][:]
        if len(words) % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _gf_mul(rcon, 2)
        words.append([words[-4][i] ^ temp[i] for i in range(4)])
    return [bytes(sum(words[4*r:4*r+4], [])) for r in range(11)]

def encrypt_block(plaintext, key):
    """Encrypt exactly one 16-byte block with an AES-128 key."""
    if len(plaintext) != 16:
        raise ValueError("Plaintext block must be exactly 16 bytes.")
    state = _to_state(plaintext)
    keys = _key_expansion(key)
    state = add_round_key(state, keys[0])
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, keys[10])
    return _from_state(state)

def decrypt_block(ciphertext, key):
    """Decrypt exactly one 16-byte block with an AES-128 key."""
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext block must be exactly 16 bytes.")
    keys = _key_expansion(key)
    state = add_round_key(_to_state(ciphertext), keys[10])
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, keys[0])
    return _from_state(state)

if __name__ == "__main__":
    # Standard AES-128 known-answer test vector.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = "69c4e0d86a7b0430d8cdb78070b4c55a"
    ciphertext = encrypt_block(plaintext, key)
    print("AES-128 educational block demo")
    print("Plaintext :", plaintext.hex())
    print("Key       :", key.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Expected  :", expected)
    print("Decrypted :", decrypt_block(ciphertext, key).hex())
    assert ciphertext.hex() == expected
    assert decrypt_block(ciphertext, key) == plaintext
    print("PASS: known-answer test and decryption test")
