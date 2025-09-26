# app.py
import os
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, jsonify
from cipher import ciphers
from werkzeug.utils import secure_filename
import io

# Initialize app
app = Flask(__name__)
app.secret_key = 'replace-with-a-secure-secret'  # replace in production
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
OUTPUT_FOLDER = os.path.join(BASE_DIR, 'outputs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

ALGO_INFO = {
    'shift': {'name': 'Shift Cipher', 'mode': 'both'},
    'substitution': {'name': 'Substitution Cipher', 'mode': 'both'},
    'affine': {'name': 'Affine Cipher', 'mode': 'both'},
    'vigenere': {'name': 'Vigenere Cipher', 'mode': 'text'},
    'hill': {'name': 'Hill Cipher', 'mode': 'text'},
    'permutation': {'name': 'Permutation Cipher', 'mode': 'both'},
    'otp': {'name': 'One-Time Pad', 'mode': 'text'},
    "playfair": {"name": "Playfair Cipher", 'mode': 'text'}
}

@app.route('/', methods=['GET'])
def index():
    # Filter algoritma sesuai mode
    text_algos = {k: v for k, v in ALGO_INFO.items() if v['mode'] in ['text', 'both']}
    file_algos = {k: v for k, v in ALGO_INFO.items() if v['mode'] == 'both'}

    return render_template(
        'index.html',
        text_algos=text_algos,
        file_algos=file_algos,
        algo_info=ALGO_INFO  # tambahan: supaya bisa dicek juga di JS
    )

# Key file upload + preview
@app.route("/upload_key", methods=["POST"])
def upload_key():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files["file"]
    try:
        content = file.read().decode("utf-8", errors="ignore")
        preview = content[:200]  # ambil hanya 200 karakter pertama
        return jsonify({
            "status": "ok",
            "preview": preview
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/process', methods=['POST'])
def process():
    action = request.form.get('action')  # encrypt or decrypt
    algo = request.form.get('algorithm')
    input_type = request.form.get('input_type', 'text')  # default to text when missing
    if input_type == "text":
        algo = request.form.get("algorithm_text")
    else:
        algo = request.form.get("algorithm_file")
    key = request.form.get('key', '')
    # Support OTP key file upload: separate field 'keyfile'
    keyfile = request.files.get('keyfile')  # optional

    if input_type == 'text':
        plaintext = request.form.get('plaintext', '')
        ciphertext_input = request.form.get('ciphertext', '')
        grouped = request.form.get('grouped') == 'on'
        try:
            # ---------------- ENCRYPT (TEXT) ----------------
            if action == 'encrypt':
                if algo == 'shift':
                    out = ciphers.shift_encrypt_text(plaintext, key)
                elif algo == 'substitution':
                    out = ciphers.substitution_encrypt_text(plaintext, key)
                elif algo == 'affine':
                    out = ciphers.affine_encrypt_text(plaintext, key)
                elif algo == 'vigenere':
                    out = ciphers.vigenere_encrypt_text(plaintext, key)
                elif algo == 'hill':
                    hill_key = request.form.getlist("hill_key[]")
                    if not hill_key or all(x.strip() == "" for x in hill_key):
                        raise ValueError("Hill key matrix required")
                    nums = [int(x) for x in hill_key if x.strip() != ""]
                    size = int(len(nums) ** 0.5)
                    if size * size != len(nums):
                        raise ValueError("Hill key size must be n*n")
                    # bentuk jadi matriks
                    key_matrix = [nums[i*size:(i+1)*size] for i in range(size)]
                    out = ciphers.hill_encrypt_text(plaintext, key_matrix)
                elif algo == 'permutation':
                    out = ciphers.permutation_encrypt_text(plaintext, key)
                elif algo == 'otp':
                    # if keyfile provided, read it
                    if keyfile and keyfile.filename != '':
                        keycontent = keyfile.read().decode('utf-8', errors='ignore')
                    else:
                        keycontent = key
                    out = ciphers.otp_encrypt_text(plaintext, keycontent)
                elif algo == 'playfair':
                    out = ciphers.playfair_encrypt_text(plaintext, key)
                else:
                    flash('Unknown algorithm')
                    return redirect(url_for('index'))
                display = ciphers.group5(out) if grouped else out
                return render_template('result.html', plaintext=plaintext, ciphertext=display, algo=ALGO_INFO[algo]['name'])
            # ---------------- DECRYPT (TEXT) ----------------
            else:
                if algo == 'shift':
                    out = ciphers.shift_decrypt_text(ciphertext_input, key)
                elif algo == 'substitution':
                    out = ciphers.substitution_decrypt_text(ciphertext_input, key)
                elif algo == 'affine':
                    out = ciphers.affine_decrypt_text(ciphertext_input, key)
                elif algo == 'vigenere':
                    out = ciphers.vigenere_decrypt_text(ciphertext_input, key)
                elif algo == 'hill':
                    hill_key = request.form.getlist("hill_key[]")
                    if not hill_key or all(x.strip() == "" for x in hill_key):
                        raise ValueError("Hill key matrix required")
                    nums = [int(x) for x in hill_key if x.strip() != ""]
                    size = int(len(nums) ** 0.5)
                    if size * size != len(nums):
                        raise ValueError("Hill key size must be n*n")
                    key_matrix = [nums[i*size:(i+1)*size] for i in range(size)]
                    out = ciphers.hill_decrypt_text(ciphertext_input, key_matrix)
                elif algo == 'permutation':
                    out = ciphers.permutation_decrypt_text(ciphertext_input, key)
                elif algo == 'otp':
                    if keyfile and keyfile.filename != '':
                        keycontent = keyfile.read().decode('utf-8', errors='ignore')
                    else:
                        keycontent = key
                    out = ciphers.otp_decrypt_text(ciphertext_input, keycontent)
                elif algo == 'playfair':
                    out = ciphers.playfair_decrypt_text(ciphertext_input, key)
                else:
                    flash('Unknown algorithm')
                    return redirect(url_for('index'))
                return render_template('result.html', plaintext=out, ciphertext=ciphertext_input, algo=ALGO_INFO[algo]['name'])
        except Exception as e:
            flash(str(e))
            return redirect(url_for('index'))

    # File mode
    file = request.files.get('file')
    if not file or file.filename == '':
        flash('No file provided for file mode')
        return redirect(url_for('index'))
    filename = secure_filename(file.filename)
    data = file.read()

    # If keyfile provided for OTP in file mode: read (rare, but support)
    if keyfile and keyfile.filename != '':
        keycontent = keyfile.read().decode('utf-8', errors='ignore')
    else:
        keycontent = key

    try:
        if action == 'encrypt':
            export_format = request.form.get('export_format', 'enc') # Default ke 'enc'

            if algo == 'shift':
                outbytes = ciphers.shift_encrypt_bytes(data, key)
            elif algo == 'substitution':
                outbytes = ciphers.substitution_encrypt_bytes(data, key)
            elif algo == 'affine':
                outbytes = ciphers.affine_encrypt_bytes(data, key)
            elif algo == 'permutation':
                outbytes = ciphers.permutation_encrypt_bytes(data, key)
            else:
                flash('Selected algorithm does not support file/binary mode')
                return redirect(url_for('index'))
            payload = ciphers.pack_encrypted_payload(filename, outbytes)
            if export_format == 'inplace':
                # Pisahkan nama file dan ekstensinya
                name, ext = os.path.splitext(filename)
                # Gabungkan kembali dengan "_encrypted" di tengah
                outname = f"{name}_encrypted{ext}" # Contoh: laporan_encrypted.pdf
            else:
                # Opsi .enc tetap sama
                outname = filename + '.enc'
            outpath = os.path.join(OUTPUT_FOLDER, outname)
            with open(outpath, 'wb') as f:
                f.write(payload)
            return send_file(outpath, as_attachment=True)
        else:  # decrypt file
            try:
                orig_name, encdata = ciphers.unpack_encrypted_payload(data)
            except Exception:
                flash('Uploaded file is not in encrypted format produced by this app')
                return redirect(url_for('index'))
            if algo == 'shift':
                dec = ciphers.shift_decrypt_bytes(encdata, key)
            elif algo == 'substitution':
                dec = ciphers.substitution_decrypt_bytes(encdata, key)
            elif algo == 'affine':
                dec = ciphers.affine_decrypt_bytes(encdata, key)
            elif algo == 'permutation':
                dec = ciphers.permutation_decrypt_bytes(encdata, key)
            else:
                flash('Selected algorithm does not support file/binary mode')
                return redirect(url_for('index'))
            # Pisahkan nama file asli (yang didapat dari payload) dan ekstensinya
            name, ext = os.path.splitext(orig_name)
            # Buat nama file output untuk hasil dekripsi
            decrypted_filename = f"{name}_decrypted{ext}" # Contoh: laporan_decrypted.pdf
            outpath = os.path.join(OUTPUT_FOLDER, decrypted_filename)
            with open(outpath, 'wb') as f:
                f.write(dec)
            return send_file(outpath, as_attachment=True)
    except Exception as e:
        flash(str(e))
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)