# tests/test_ciphers.py
import tempfile
import sys, os, random
import pytest
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from cipher import ciphers
import string

# --- Text-based ciphers ---
def test_shift_text_roundtrip():
    pt = "HELLOWORLD"
    key = "3"
    c = ciphers.shift_encrypt_text(pt, key)
    d = ciphers.shift_decrypt_text(c, key)
    assert d == pt

def test_shift_text_with_negative_key():
    pt = "HELLO"
    key = "-3"
    c = ciphers.shift_encrypt_text(pt, key)
    d = ciphers.shift_decrypt_text(c, key)
    assert d == pt

def test_substitution_text_roundtrip():
    pt = "CRYPTOGRAPHY"
    mapping = "QWERTYUIOPASDFGHJKLZXCVBNM"
    c = ciphers.substitution_encrypt_text(pt, mapping)
    d = ciphers.substitution_decrypt_text(c, mapping)
    assert d == ''.join([ch for ch in pt.upper() if ch.isalpha()])

def test_substitution_text_invalid_mapping():
    pt = "HELLO"
    # mapping must have 26 unique chars
    bad_mapping = "ABCDE"  
    with pytest.raises(ValueError):
        ciphers.substitution_encrypt_text(pt, bad_mapping)

def test_affine_text_roundtrip():
    pt = "SECUREDATA"
    key = "5,8"  # 5 coprime with 26
    c = ciphers.affine_encrypt_text(pt, key)
    d = ciphers.affine_decrypt_text(c, key)
    assert d == ''.join([ch for ch in pt.upper() if ch.isalpha()])

def test_affine_invalid_key():
    pt = "HELLO"
    # a must be coprime with 26
    bad_key = "13,5"
    with pytest.raises(ValueError):
        ciphers.affine_encrypt_text(pt, bad_key)

def test_vigenere_roundtrip():
    pt = "HELLOWORLD"
    key = "KEY"
    c = ciphers.vigenere_encrypt_text(pt, key)
    d = ciphers.vigenere_decrypt_text(c, key)
    assert d == pt

def test_vigenere_with_nonalpha_chars():
    pt = "HELLO123!"
    key = "KEY"
    c = ciphers.vigenere_encrypt_text(pt, key)
    d = ciphers.vigenere_decrypt_text(c, key)
    assert d == pt

def test_hill_roundtrip_2x2():
    pt = "TESTING"
    # 2x2 key (3 3; 2 5) from common Hill examples
    key = [[3, 3], [2, 5]]   # sekarang dalam bentuk matriks list of lists
    c = ciphers.hill_encrypt_text(pt, key)
    d = ciphers.hill_decrypt_text(c, key)
    # Note: plaintext may be padded with X; so compare prefix
    assert d.startswith("TESTING")

def test_hill_invalid_matrix_size():
    pt = "TEST"
    bad_key = [[1, 2, 3]]  # not square
    with pytest.raises(ValueError):
        ciphers.hill_encrypt_text(pt, bad_key)

def test_permutation_roundtrip():
    pt = "ABCDEFGH"
    key = "2,0,1"
    c = ciphers.permutation_encrypt_text(pt, key)
    d = ciphers.permutation_decrypt_text(c, key)
    assert d.startswith("ABCDEFGH") or d.startswith("ABCDEFGHX")  # pad possible

def test_permutation_invalid_key():
    pt = "HELLO"
    bad_key = "0,0,1"  # duplicate indices
    with pytest.raises(ValueError):
        ciphers.permutation_encrypt_text(pt, bad_key)

def test_otp_roundtrip():
    pt = "HELLOWORLD"
    key = "XMCKLXMCKL"  # example OTP-length key
    c = ciphers.otp_encrypt_text(pt, key)
    d = ciphers.otp_decrypt_text(c, key)
    assert d == pt

def test_otp_wrong_key_length():
    pt = "HELLO"
    bad_key = "SH"   # shorter than 5 letters
    with pytest.raises(ValueError):
        ciphers.otp_encrypt_text(pt, bad_key)

def test_playfair_example():
    plaintext = "INSTRUMENTS"
    key = "MONARCHY"
    expected = "GATLMZCLRQXA"
    result = ciphers.playfair_encrypt_text(plaintext, key)
    assert result == expected

def test_playfair_decrypt_example():
    ciphertext = "GATLMZCLRQXA"
    key = "MONARCHY"
    expected = "INSTRUMENTSX"
    result = ciphers.playfair_decrypt_text(ciphertext, key)
    assert result == expected

# --- Bytes-based ciphers ---
def test_shift_bytes_roundtrip():
    data = b'\x00\x01\x02\xFF'
    key = "10"
    c = ciphers.shift_encrypt_bytes(data, key)
    d = ciphers.shift_decrypt_bytes(c, key)
    assert d == data

def test_shift_bytes_large_key():
    data = b"testdata"
    key = str(300)  # effectively key % 256
    c = ciphers.shift_encrypt_bytes(data, key)
    d = ciphers.shift_decrypt_bytes(c, key)
    assert d == data

def test_substitution_bytes_roundtrip(tmp_path):
    data = b'hello world \x00\xff'
    key = "my secret key"
    c = ciphers.substitution_encrypt_bytes(data, key)
    d = ciphers.substitution_decrypt_bytes(c, key)
    assert d == data

def test_substitution_bytes_randomized():
    data = bytes([random.randint(0, 255) for _ in range(1000)])
    key = "randkey"
    c = ciphers.substitution_encrypt_bytes(data, key)
    d = ciphers.substitution_decrypt_bytes(c, key)
    assert d == data

def test_affine_bytes_roundtrip():
    data = b'\x00\x10\x20'
    key = "5,7"  # a=5 coprime with 256
    c = ciphers.affine_encrypt_bytes(data, key)
    d = ciphers.affine_decrypt_bytes(c, key)
    assert d == data

def test_affine_bytes_invalid_key():
    data = b"data"
    bad_key = "2,5"  # gcd(2,256)!=1 → invalid
    with pytest.raises(ValueError):
        ciphers.affine_encrypt_bytes(data, bad_key)

def test_permutation_bytes_roundtrip():
    data = b'\x00\x01\x02\x03\x04'
    key = "permkey"
    c = ciphers.permutation_encrypt_bytes(data, key)
    d = ciphers.permutation_decrypt_bytes(c, key)
    assert d == data

def test_permutation_bytes_different_keys():
    data = b"same message"
    key1 = "keyone"
    key2 = "keytwo"
    c1 = ciphers.permutation_encrypt_bytes(data, key1)
    c2 = ciphers.permutation_encrypt_bytes(data, key2)
    # ciphertext must differ if keys differ
    assert c1 != c2

def test_otp_bytes_exact_length():
    pt = b"abcdef"
    key = "ABCDEF"  # exactly 6 chars = 6 bytes
    c = ciphers.otp_encrypt_text(pt.decode(), key)
    d = ciphers.otp_decrypt_text(c, key)
    assert d == pt.decode()