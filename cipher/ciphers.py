# cipher/ciphers.py
import string
import numpy as np
from sympy import Matrix
from math import gcd
import json
import hashlib

ALPHABET = string.ascii_uppercase # A-Z
ALPHABET_SIZE = 26

# ------------------ Helpers ------------------

def normalize_text_for_letters(s):
    """Keep letters only, uppercase."""
    return ''.join([c for c in s.upper() if c.isalpha()])

def group5(s):
    return ' '.join([s[i:i+5] for i in range(0, len(s), 5)])

# ---------- Shift Cipher (letter-mode and byte-mode) ----------

def shift_encrypt_text(plaintext, key):
    k = int(key) % ALPHABET_SIZE
    pt = normalize_text_for_letters(plaintext)
    out = []
    for ch in pt:
        idx = ALPHABET.index(ch)
        out.append(ALPHABET[(idx + k) % ALPHABET_SIZE])
    return ''.join(out)

def shift_decrypt_text(ciphertext, key):
    k = int(key) % ALPHABET_SIZE
    out = []
    for ch in ciphertext:
        idx = ALPHABET.index(ch)
        out.append(ALPHABET[(idx - k) % ALPHABET_SIZE])
    return ''.join(out)

# -----------------------------
# Shift Cipher (bytes)
# -----------------------------

# byte-wise
def shift_encrypt_bytes(data: bytes, key):
    k = int(key) % 256
    return bytes([(b + k) % 256 for b in data])

def shift_decrypt_bytes(data: bytes, key):
    k = int(key) % 256
    return bytes([(b - k) % 256 for b in data])

# ---------- Substitution Cipher ----------

def substitution_encrypt_text(plaintext, key_mapping_str):
    """
    key_mapping_str: 26-char string mapping A..Z to cipher letters.
    Example: "QWERTYUIOPASDFGHJKLZXCVBNM"
    """
    if len(key_mapping_str) != 26 or not key_mapping_str.isalpha():
        raise ValueError("Key must be 26 alphabetic characters")
    mapping = {ALPHABET[i]: key_mapping_str.upper()[i] for i in range(26)}
    pt = normalize_text_for_letters(plaintext)
    return ''.join(mapping[c] for c in pt)

def substitution_decrypt_text(ciphertext, key_mapping_str):
    if len(key_mapping_str) != 26 or not key_mapping_str.isalpha():
        raise ValueError("Key must be 26 alphabetic characters")
    mapping = {key_mapping_str.upper()[i]: ALPHABET[i] for i in range(26)}
    return ''.join(mapping[c] for c in ciphertext)

# -----------------------------
# Substitution Cipher (bytes)
# -----------------------------

# byte-wise substitution using a 256-length mapping derived from key
def make_byte_subst_from_key(key: str):
    # deterministically generate a permutation of 0..255 using key as seed
    seed_bytes = hashlib.sha256(key.encode("utf-8")).digest()
    seed_int = int.from_bytes(seed_bytes[:8], "big") % (2**32)  # fix: force into 32-bit range
    rng = np.random.RandomState(seed_int)
    perm = list(range(256))
    rng.shuffle(perm)
    return bytes(perm)

def substitution_encrypt_bytes(data: bytes, key: str) -> bytes:
    """Encrypt data with substitution cipher derived from key"""
    table = make_byte_subst_from_key(key)
    return bytes([table[b] for b in data])

def substitution_decrypt_bytes(data: bytes, key: str) -> bytes:
    """Decrypt data with substitution cipher derived from key"""
    table = make_byte_subst_from_key(key)
    inv = [0] * 256
    for i, v in enumerate(table):
        inv[v] = i
    return bytes([inv[b] for b in data])

# ---------- Affine Cipher (text mode mod26) ----------

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('No modular inverse')
    return x % m

def affine_encrypt_text(plaintext, a_b):
    # a_b is string like "a,b"
    a, b = map(int, a_b.split(','))
    if egcd(a, ALPHABET_SIZE)[0] != 1:
        raise ValueError('a must be coprime with 26')
    pt = normalize_text_for_letters(plaintext)
    out = []
    for c in pt:
        x = ALPHABET.index(c)
        out.append(ALPHABET[(a*x + b) % ALPHABET_SIZE])
    return ''.join(out)

def affine_decrypt_text(ciphertext, a_b):
    a, b = map(int, a_b.split(','))
    inva = modinv(a, ALPHABET_SIZE)
    out = []
    for c in ciphertext:
        y = ALPHABET.index(c)
        out.append(ALPHABET[(inva*(y - b)) % ALPHABET_SIZE])
    return ''.join(out)

# -----------------------------
# Affine Cipher (bytes)
# -----------------------------

# byte-wise affine modulo 256
def affine_encrypt_bytes(data: bytes, a_b):
    try:
        a, b = map(int, a_b.split(','))
    except Exception:
        raise ValueError("Key must be in format 'a,b'")
    if egcd(a, 256)[0] != 1:
        raise ValueError("Parameter 'a' must be coprime with 256")
    return bytes([(a * b0 + b) % 256 for b0 in data])

def affine_decrypt_bytes(data: bytes, a_b):
    try:
        a, b = map(int, a_b.split(','))
    except Exception:
        raise ValueError("Key must be in format 'a,b'")
    inva = modinv(a, 256)
    if inva is None:
        raise ValueError("'a' has no modular inverse mod 256")
    return bytes([(inva * (b0 - b)) % 256 for b0 in data])

# ---------- Vigenere Cipher (letter-mode only) ----------

def vigenere_encrypt_text(plaintext, key):
    """
    Vigenere encryption (alphabet-only mode):
    - Ignores all non-letter characters (they are removed)
    - Uses only letters from key
    - Output: only letters A-Z/a-z
    """
    key_letters = [ch.upper() for ch in key if ch.isalpha()]
    if not key_letters:
        raise ValueError("Key must contain at least one letter A-Z")

    filtered_plain = [ch for ch in plaintext if ch.isalpha()]  # only keep letters
    out = []
    ki = 0
    for ch in filtered_plain:
        k = ord(key_letters[ki % len(key_letters)]) - ord('A')
        if ch.isupper():
            base = ord('A')
        else:
            base = ord('a')
        out_char = chr((ord(ch) - base + k) % 26 + base)
        out.append(out_char)
        ki += 1
    return ''.join(out)

def vigenere_decrypt_text(ciphertext, key):
    """
    Vigenere decryption (alphabet-only mode):
    - Ignores all non-letter characters (they are removed)
    - Output: only letters A-Z/a-z
    """
    key_letters = [ch.upper() for ch in key if ch.isalpha()]
    if not key_letters:
        raise ValueError("Key must contain at least one letter A-Z")

    filtered_ciph = [ch for ch in ciphertext if ch.isalpha()]  # only keep letters
    out = []
    ki = 0
    for ch in filtered_ciph:
        k = ord(key_letters[ki % len(key_letters)]) - ord('A')
        if ch.isupper():
            base = ord('A')
        else:
            base = ord('a')
        out_char = chr((ord(ch) - base - k) % 26 + base)
        out.append(out_char)
        ki += 1
    return ''.join(out)

# ---------- Hill Cipher (letter-mode) ----------

# def parse_hill_key(key: str):
#     # Terima input dengan spasi atau koma
#     parts = key.replace(",", " ").split()
#     nums = list(map(int, parts))
#     n = int(len(nums) ** 0.5)
#     if n * n != len(nums):
#         raise ValueError("Hill key must form an n×n square matrix (length n^2).")
#     K = Matrix(np.array(nums).reshape((n, n)))
#     det = int(K.det()) % ALPHABET_SIZE
#     # Validasi invertibility (det gcd 26 == 1)
#     if egcd(det, ALPHABET_SIZE)[0] != 1:
#         raise ValueError("Hill key matrix is not invertible modulo 26")
#     return K

def hill_encrypt_text(plaintext, key_matrix):
    """
    plaintext: string (letters A-Z)
    key_matrix: list of list of int (n x n)
    """
    pt = normalize_text_for_letters(plaintext)
    K = Matrix(key_matrix)
    n = K.shape[0]
    out = ''
    # pad
    while len(pt) % n != 0:
        pt += 'X'
    for i in range(0, len(pt), n):
        vec = Matrix([ALPHABET.index(c) for c in pt[i:i+n]])
        res = (K * vec) % ALPHABET_SIZE
        out += ''.join(ALPHABET[int(x)] for x in res)
    return out

def hill_decrypt_text(ciphertext, key_matrix):
    K = Matrix(key_matrix)
    n = K.shape[0]
    Kinv = K.inv_mod(ALPHABET_SIZE)
    out = ''
    for i in range(0, len(ciphertext), n):
        vec = Matrix([ALPHABET.index(c) for c in ciphertext[i:i+n]])
        res = (Kinv * vec) % ALPHABET_SIZE
        out += ''.join(ALPHABET[int(x)] for x in res)
    return out

# ---------- Permutation Cipher ----------

def permutation_encrypt_text(plaintext, key_permutation):
    """
    key_permutation: comma-separated indices (e.g. "2,0,1").
    """
    try:
        perm = list(map(int, key_permutation.split(',')))
    except Exception:
        raise ValueError("Key must be comma-separated integers")
    k = len(perm)
    if sorted(perm) != list(range(k)):
        raise ValueError("Key permutation must be a valid permutation of 0..k-1")

    pt = normalize_text_for_letters(plaintext)
    while len(pt) % k != 0:
        pt += 'X'  # pad with X

    out = ''
    for i in range(0, len(pt), k):
        block = pt[i:i+k]
        out += ''.join(block[perm[j]] for j in range(k))
    return out

def permutation_decrypt_text(ciphertext, key_permutation):
    try:
        perm = list(map(int, key_permutation.split(',')))
    except Exception:
        raise ValueError("Key must be comma-separated integers")
    k = len(perm)
    if sorted(perm) != list(range(k)):
        raise ValueError("Key permutation must be a valid permutation of 0..k-1")

    inv = [0] * k
    for i, p in enumerate(perm):
        inv[p] = i

    out = ''
    for i in range(0, len(ciphertext), k):
        block = ciphertext[i:i+k]
        out += ''.join(block[inv[j]] for j in range(k))
    return out

# -----------------------------
# Permutation Cipher (bytes)
# -----------------------------

# byte-wise permutation: derive permutation of indices from key (for small files)
# but for large files, we implement a stream-permutation by generating a keystream of positions

def permutation_encrypt_bytes(data: bytes, key: str) -> bytes:
    """
    Pseudo-random stream cipher using XOR.
    Generates mask deterministically from key using numpy PRNG.
    """
    seed_bytes = hashlib.sha256(key.encode("utf-8")).digest()
    seed_int = int.from_bytes(seed_bytes[:8], "big") % (2**32)  # fix: force into 32-bit range
    rng = np.random.RandomState(seed_int)

    mask = rng.randint(0, 256, size=len(data), dtype=np.uint8)
    return bytes([b ^ int(mask[i]) for i, b in enumerate(data)])

def permutation_decrypt_bytes(data: bytes, key: str) -> bytes:
    """Decryption is symmetric since XOR is its own inverse"""
    return permutation_encrypt_bytes(data, key)

# ---------- One-Time Pad (text-mode only) ----------

def otp_encrypt_text(plaintext, keytext):
    """
    OTP (alphabet letters only, non-letters removed in output).
    - Only alphabet letters are encrypted
    - Non-letters in plaintext are ignored (not included in output)
    - Uses letters from keytext only
    - Key must have at least as many letters as the plaintext letters
    """
    key_letters = [ch.upper() for ch in keytext if ch.isalpha()]
    letters_needed = sum(1 for ch in plaintext if ch.isalpha())
    if len(key_letters) < letters_needed:
        raise ValueError(f'Key file shorter than plaintext for OTP (need at least {letters_needed} letters)')

    out = []
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            p_idx = ord(ch.upper()) - ord('A')
            k_idx = ord(key_letters[ki]) - ord('A')
            res_idx = (p_idx + k_idx) % 26
            res_ch = chr(res_idx + ord('A'))
            # case preserved
            if ch.islower():
                res_ch = res_ch.lower()
            out.append(res_ch)
            ki += 1
        # else: skip non-alpha (do not append)

    return ''.join(out)

def otp_decrypt_text(ciphertext, keytext):
    """
    OTP decryption (alphabet letters only, non-letters removed).
    - Only alphabet letters are decrypted
    - Non-letters in ciphertext are ignored (not included in output)
    - Uses letters from keytext only
    - Key must have at least as many letters as ciphertext letters
    """
    key_letters = [ch.upper() for ch in keytext if ch.isalpha()]
    letters_needed = sum(1 for ch in ciphertext if ch.isalpha())
    if len(key_letters) < letters_needed:
        raise ValueError(f'Key file shorter than ciphertext for OTP (need at least {letters_needed} letters)')

    out = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            c_idx = ord(ch.upper()) - ord('A')
            k_idx = ord(key_letters[ki]) - ord('A')
            res_idx = (c_idx - k_idx) % 26
            res_ch = chr(res_idx + ord('A'))
            if ch.islower():
                res_ch = res_ch.lower()
            out.append(res_ch)
            ki += 1
        # else: skip non-alpha (do not append)

    return ''.join(out)

# ---------- Playfair Cipher (classic: I/J combined -> 5x5) ----------
# Note: this implementation treats 'J' as 'I' (classic Playfair).
PLAYFAIR_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is omitted (I/J combined)

def _playfair_prepare_key(key: str):
    """
    Build 5x5 Playfair table from key.
    - Key can contain non-letters; only letters used.
    - 'J' in key or plaintext is treated as 'I'.
    """
    key = (key or "").upper()
    seen = []
    for ch in key:
        if not ch.isalpha():
            continue
        if ch == 'J':
            ch = 'I'
        if ch not in seen and ch in PLAYFAIR_ALPHABET:
            seen.append(ch)
    # fill remaining letters
    for ch in PLAYFAIR_ALPHABET:
        if ch not in seen:
            seen.append(ch)
    # to 5x5 matrix
    table = [seen[i*5:(i+1)*5] for i in range(5)]
    return table

def _playfair_find_position(table, ch):
    """Return (row, col) in 5x5 table for ch."""
    for r in range(5):
        for c in range(5):
            if table[r][c] == ch:
                return r, c
    raise ValueError(f"Character {ch} not found in Playfair table")

def _playfair_prepare_text(s: str):
    """
    Prepare plaintext/ciphertext for Playfair:
    - uppercase, remove non-letters
    - replace 'J' by 'I'
    """
    s = (s or "").upper()
    s = ''.join(ch for ch in s if ch.isalpha())
    s = s.replace('J', 'I')
    return s

def playfair_encrypt_text(plaintext: str, key: str) -> str:
    """
    Encrypt using Playfair (classic I/J combined).
    Only letters are processed; non-letters are ignored (removed).
    """
    pt = _playfair_prepare_text(plaintext)
    table = _playfair_prepare_key(key)

    # build digraphs: insert X between repeated letters in a pair
    digraphs = []
    i = 0
    while i < len(pt):
        a = pt[i]
        b = pt[i+1] if i+1 < len(pt) else None
        if b is None:
            digraphs.append((a, 'X'))
            i += 1
        elif a == b:
            digraphs.append((a, 'X'))
            i += 1
        else:
            digraphs.append((a, b))
            i += 2

    out_chars = []
    for a, b in digraphs:
        ra, ca = _playfair_find_position(table, a)
        rb, cb = _playfair_find_position(table, b)
        if ra == rb:
            # same row -> take right
            out_chars.append(table[ra][(ca + 1) % 5])
            out_chars.append(table[rb][(cb + 1) % 5])
        elif ca == cb:
            # same column -> take down
            out_chars.append(table[(ra + 1) % 5][ca])
            out_chars.append(table[(rb + 1) % 5][cb])
        else:
            # rectangle swap
            out_chars.append(table[ra][cb])
            out_chars.append(table[rb][ca])
    return ''.join(out_chars)

def playfair_decrypt_text(ciphertext: str, key: str) -> str:
    """
    Decrypt Playfair ciphertext. Assumes ciphertext is letters-only (prepared).
    Result may contain padding 'X' inserted during encryption.
    """
    ct = _playfair_prepare_text(ciphertext)
    table = _playfair_prepare_key(key)

    out_chars = []
    # process two-by-two
    for i in range(0, len(ct), 2):
        a = ct[i]
        b = ct[i+1]
        ra, ca = _playfair_find_position(table, a)
        rb, cb = _playfair_find_position(table, b)
        if ra == rb:
            out_chars.append(table[ra][(ca - 1) % 5])
            out_chars.append(table[rb][(cb - 1) % 5])
        elif ca == cb:
            out_chars.append(table[(ra - 1) % 5][ca])
            out_chars.append(table[(rb - 1) % 5][cb])
        else:
            out_chars.append(table[ra][cb])
            out_chars.append(table[rb][ca])
    return ''.join(out_chars)

# ---------- Utilities for file packaging ----------

def pack_encrypted_payload(original_filename, data: bytes):
    # store a small JSON header followed by raw bytes
    header = json.dumps({
        'filename': original_filename
    }).encode('utf-8')
    sep = b'\n--ENCRYPTED-DATA-START--\n'
    return header + sep + data

def unpack_encrypted_payload(packed: bytes):
    sep = b'\n--ENCRYPTED-DATA-START--\n'
    idx = packed.find(sep)
    if idx == -1:
        raise ValueError('Invalid payload')
    header = json.loads(packed[:idx].decode('utf-8'))
    data = packed[idx+len(sep):]
    return header.get('filename', 'output'), data