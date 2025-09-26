# Flask Cryptosystem WebApp

## Deskripsi Singkat
Aplikasi Web Edukasi untuk Mengimplementasikan Cipher Clasic (Shift, Substitution, Affine, Vigenere, Hill, Permutation, dan Playfair) serta varian byte-wise untuk beberapa cipher yang mendukung enkripsi file. Juga mendukung One-Time Pad (text-mode) dengan upload key file.

## Struktur Project
flask-cryptosystem/
- app.py
- requirements.txt
- cipher/
  - ciphers.py
- templates/
  - base.html, index.html, result.html
- static/
  - styles.css, main.js
- tests/
  - test_ciphers.py
- uploads/ (runtime)
- outputs/ (runtime)
- venv/ (install dahulu)
- .gitignore

## Cara Menjalankan
1. Buat virtualenv:
   `python -m venv venv`
2. Install dependencies:
   `pip install -r requirements.txt`
3. Jalankan:
   `python app.py` or `flask run`
Lalu buka, http://127.0.0.1:5000

<!-- Notes:
- The app supports encryption/decryption for both text and file inputs.
- For text: you can choose an algorithm and key, and result will be shown on page.
- For files: upload file, choose algorithm and key, produce encrypted `.dat` file containing a small JSON header (original filename+ext) followed by encrypted payload.
- Algorithms that operate on alphabetic A-Z only (Vigenere, Hill in letter-mode, OTP text-mode) will only process letters and ignore/discard other characters per assignment rules when outputting ciphertext for text mode.
- For file/binary mode, a bytewise variant of ciphers is used (add mod256, substitution table over 0..255, affine mod256, permutation over byte positions derived from key). This keeps arbitrary files encryptable. -->

## Catatan penting & tips
- Vigenere, Hill, OTP: **text-mode only** (A-Z). Non-letter characters akan diabaikan.
- Untuk file encryption, gunakan Shift/Substitution/Affine/Permutation yang punya varian byte-wise.
- File terenkripsi menyimpan header JSON kecil sehingga saat dekripsi nama file asli dipulihkan.
- Untuk One-Time Pad: gunakan file kunci yang berisi huruf (A-Z) cukup panjang. Jika key lebih pendek dari plaintext, dekripsi tidak akan benar.
- Hill cipher: masukkan matrix key sebagai bilangan row-wise (mis token dipisah spasi). Matrix harus invertible mod 26.

## Limitations
- Implementasi untuk pembelajaran; tidak cocok untuk penggunaan produksi.
- Byte-substitution menggunakan PRNG deterministik dari key (bukan CSPRNG).

## Contoh Quick-test
- Text: Pilih 'Vigenere', Plaintext: 'HELLO WORLD 123', Key: 'KEY' => hasil ciphertext huruf-only (spasi, angka diabaikan). Lalu, klik Decrypt (paste ciphertext) dengan key 'KEY' → harus kembali ke 'HELLOWORLD' (karena non-letters diabaikan per requirement).
- File: Encrypt any jpg with Affine (a must be odd and coprime with 256) using key "5,8" lalu decrypt kembali.