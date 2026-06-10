import os
import sqlite3
import hashlib
import secrets
import base64
from io import BytesIO
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import qrcode
from cryptography.fernet import Fernet

app = Flask(__name__)
# Menetapkan secret key untuk session flash messages Flask
app.secret_key = secrets.token_hex(24)

# Menentukan path absolut database dan file secret key Fernet
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'batikcert.db')
KEY_PATH = os.path.join(INSTANCE_DIR, 'secret.key')

# Helper untuk mendapatkan koneksi database SQLite
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Helper untuk meload kunci Fernet (AES)
def get_fernet_cipher():
    # Coba baca kunci dari environment variable (sangat disarankan untuk platform cloud seperti Railway)
    env_key = os.environ.get('FERNET_SECRET_KEY')
    if env_key:
        return Fernet(env_key.encode('utf-8'))

    if not os.path.exists(KEY_PATH):
        # Jika kunci belum ada, buat kunci baru
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        key = Fernet.generate_key()
        with open(KEY_PATH, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_PATH, 'rb') as key_file:
            key = key_file.read()
    return Fernet(key)

# Helper untuk menghitung digest SHA-256
def calculate_sha256(nama, desainer, tanggal, kategori):
    # Menggabungkan data dengan delimiter pipe '|' sesuai spesifikasi
    data_str = f"{nama}|{desainer}|{tanggal}|{kategori}"
    return hashlib.sha256(data_str.encode('utf-8')).hexdigest()


# ROUTE: GET /
# Halaman Utama - Menampilkan daftar karya batik, statistik, dan form modal tambah/edit
@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Mengambil semua karya batik
    cursor.execute('SELECT * FROM artworks')
    artworks_rows = cursor.fetchall()

    # Mengambil data status token verifikasi
    cursor.execute('SELECT token, used FROM verification_tokens')
    tokens_rows = cursor.fetchall()
    
    # Membuat mapping token plaintext ke status 'used' untuk pencarian cepat
    token_status_map = {row['token']: row['used'] for row in tokens_rows}

    # Dekripsi token untuk mencocokkan status 'used'
    fernet = get_fernet_cipher()
    artworks = []
    
    category_counts = {}
    total_artworks = 0

    for row in artworks_rows:
        art = dict(row)
        total_artworks += 1
        
        # Hitung statistik per kategori
        kategori = art['kategori']
        category_counts[kategori] = category_counts.get(kategori, 0) + 1

        # Dekripsi token untuk mendapatkan plaintext token asli
        try:
            decrypted_bytes = fernet.decrypt(art['encrypted_token'].encode('utf-8'))
            plaintext_token = decrypted_bytes.decode('utf-8')
            # Ambil status 'used' dari mapping database (default ke 1 jika tidak ditemukan untuk keamanan)
            art['used'] = token_status_map.get(plaintext_token, 1)
        except Exception:
            # Jika dekripsi gagal, set status used = 1 (tidak valid/used)
            art['used'] = 1

        artworks.append(art)

    # Ambil statistik jumlah karya per kategori (diurutkan alfabetis)
    # Gunakan default kategori agar stat card selalu rapi di UI
    default_categories = ["Batik Geometris", "Batik Islami", "Batik Fraktal"]
    category_stats = {}
    for cat in default_categories:
        category_stats[cat] = category_counts.get(cat, 0)
    
    # Masukkan kategori lainnya jika ada
    for cat, count in category_counts.items():
        if cat not in default_categories:
            category_stats[cat] = count

    conn.close()

    return render_template(
        'index.html', 
        artworks=artworks, 
        total_artworks=total_artworks, 
        category_stats=category_stats
    )


# ROUTE: POST /tambah
# Menambahkan karya batik baru ke dalam database
@app.route('/tambah', methods=['POST'])
def add_artwork():
    nama = request.form.get('nama_karya', '').strip()
    desainer = request.form.get('desainer', '').strip()
    tanggal = request.form.get('tanggal_dibuat', '').strip()
    kategori_select = request.form.get('kategori', '').strip()
    custom_kategori = request.form.get('custom_kategori', '').strip()

    # Tentukan kategori (gunakan kustom jika opsi 'Lainnya' dipilih)
    kategori = custom_kategori if kategori_select == 'Lainnya' else kategori_select

    if not nama or not desainer or not tanggal or not kategori:
        flash("Semua input data karya batik wajib diisi!", "error")
        return redirect(url_for('index'))

    # 1. Hitung SHA-256 digest dari metadata karya
    digest = calculate_sha256(nama, desainer, tanggal, kategori)

    # 2. Buat token verifikasi unik baru
    plaintext_token = secrets.token_urlsafe(32)

    # 3. Simpan token verifikasi ke tabel verification_tokens (used = 0)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO verification_tokens (token, used) VALUES (?, ?)',
            (plaintext_token, 0)
        )
        
        # 4. Enkripsi token verifikasi menggunakan Fernet (AES)
        fernet = get_fernet_cipher()
        encrypted_token_bytes = fernet.encrypt(plaintext_token.encode('utf-8'))
        encrypted_token_str = encrypted_token_bytes.decode('utf-8')

        # 5. Simpan karya batik ke tabel artworks
        cursor.execute('''
            INSERT INTO artworks (nama_karya, desainer, tanggal_dibuat, kategori, digest_sha256, encrypted_token)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (nama, desainer, tanggal, kategori, digest, encrypted_token_str))
        
        conn.commit()
        flash(f"Karya batik '{nama}' berhasil didaftarkan secara kriptografis!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Gagal mendaftarkan karya batik: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('index'))


# ROUTE: POST /edit/<id>
# Mengubah data karya batik yang sudah terdaftar
@app.route('/edit/<int:art_id>', methods=['POST'])
def edit_artwork(art_id):
    nama = request.form.get('nama_karya', '').strip()
    desainer = request.form.get('desainer', '').strip()
    tanggal = request.form.get('tanggal_dibuat', '').strip()
    kategori_select = request.form.get('kategori', '').strip()
    custom_kategori = request.form.get('custom_kategori', '').strip()

    # Tentukan kategori
    kategori = custom_kategori if kategori_select == 'Lainnya' else kategori_select

    if not nama or not desainer or not tanggal or not kategori:
        flash("Semua input data karya batik wajib diisi!", "error")
        return redirect(url_for('index'))

    # Recalculate digest SHA-256 berdasarkan data baru
    new_digest = calculate_sha256(nama, desainer, tanggal, kategori)

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Update data di tabel artworks
        cursor.execute('''
            UPDATE artworks 
            SET nama_karya = ?, desainer = ?, tanggal_dibuat = ?, kategori = ?, digest_sha256 = ?
            WHERE id = ?
        ''', (nama, desainer, tanggal, kategori, new_digest, art_id))
        
        conn.commit()
        flash("Data karya batik berhasil diperbarui!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Gagal memperbarui karya batik: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('index'))


# ROUTE: POST /hapus/<id>
# Menghapus data karya batik beserta token verifikasi terkait
@app.route('/hapus/<int:art_id>', methods=['POST'])
def delete_artwork(art_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Ambil encrypted token untuk menghapus record di verification_tokens
        cursor.execute('SELECT encrypted_token FROM artworks WHERE id = ?', (art_id,))
        art = cursor.fetchone()
        
        if art:
            encrypted_token = art['encrypted_token']
            
            # Dekripsi untuk mendapatkan token plaintext asli
            fernet = get_fernet_cipher()
            try:
                decrypted_bytes = fernet.decrypt(encrypted_token.encode('utf-8'))
                plaintext_token = decrypted_bytes.decode('utf-8')
                
                # Hapus token verifikasi
                cursor.execute('DELETE FROM verification_tokens WHERE token = ?', (plaintext_token,))
            except Exception:
                # Abaikan jika dekripsi gagal ketika menghapus token
                pass
            
            # Hapus karya batik
            cursor.execute('DELETE FROM artworks WHERE id = ?', (art_id,))
            conn.commit()
            flash("Karya batik dan data keamanan terkait berhasil dihapus!", "success")
        else:
            flash("Karya batik tidak ditemukan!", "error")
    except Exception as e:
        conn.rollback()
        flash(f"Gagal menghapus karya batik: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('index'))


# ROUTE: GET /preview/<id>
# Menampilkan preview sertifikat keaslian karya batik digital
@app.route('/preview/<int:art_id>')
def preview_certificate(art_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM artworks WHERE id = ?', (art_id,))
    art_row = cursor.fetchone()
    
    if not art_row:
        conn.close()
        flash("Sertifikat tidak ditemukan!", "error")
        return redirect(url_for('index'))
        
    art = dict(art_row)
    
    # Cek status 'used' token verifikasi
    cursor.execute('SELECT token, used FROM verification_tokens')
    tokens_rows = cursor.fetchall()
    token_status_map = {row['token']: row['used'] for row in tokens_rows}
    
    fernet = get_fernet_cipher()
    try:
        decrypted_bytes = fernet.decrypt(art['encrypted_token'].encode('utf-8'))
        plaintext_token = decrypted_bytes.decode('utf-8')
        art['used'] = token_status_map.get(plaintext_token, 1)
    except Exception:
        art['used'] = 1
        
    conn.close()

    # Tanggal penerbitan sertifikat (Hari ini)
    today_str = datetime.now().strftime('%d %B %Y')
    
    return render_template(
        'preview.html', 
        art=art, 
        tgl_penerbitan=today_str, 
        css_content=None, 
        qr_base64=None
    )


# ROUTE: GET /qrcode/<token>
# Mengembalikan gambar QR Code dinamis berisi link verifikasi terenkripsi
@app.route('/qrcode/<token>')
def get_qrcode(token):
    # Buat tautan verifikasi lengkap
    verify_url = url_for('verify_certificate', token=token, _external=True)
    
    # Membuat QR Code menggunakan modul qrcode dan Pillow
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(verify_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="#5C3A21", back_color="#FDFBF7") # Warna brand cokelat & ivory
    
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')


# ROUTE: GET /download-pdf/<id>
# Mengunduh sertifikat keaslian dalam format PDF menggunakan WeasyPrint
@app.route('/download-pdf/<int:art_id>')
def download_pdf(art_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM artworks WHERE id = ?', (art_id,))
    art_row = cursor.fetchone()
    
    if not art_row:
        conn.close()
        flash("Sertifikat tidak ditemukan!", "error")
        return redirect(url_for('index'))
        
    art = dict(art_row)
    conn.close()

    # 1. Baca isi static/style.css secara lokal untuk di-inject agar terhindar dari deadlock
    css_content = ""
    css_path = os.path.join(BASE_DIR, 'static', 'style.css')
    if os.path.exists(css_path):
        with open(css_path, 'r', encoding='utf-8') as css_file:
            css_content = css_file.read()
            # Hapus import font eksternal untuk menghindari error ijin temp file reportlab di Windows
            if "@import url" in css_content:
                lines = css_content.splitlines()
                lines = [line for line in lines if "@import url" not in line]
                css_content = "\n".join(lines)
            # Hapus bagian animasi dan inline variabel untuk kecocokan xhtml2pdf
            if "/* Animations */" in css_content:
                css_content = css_content.split("/* Animations */")[0]
            css_content = css_content.replace('var(--primary-color)', '#8C6239')
            css_content = css_content.replace('var(--primary-light)', '#C29B68')
            css_content = css_content.replace('var(--primary-dark)', '#5C3A21')
            css_content = css_content.replace('var(--secondary-color)', '#D4AF37')
            css_content = css_content.replace('var(--dark-bg)', '#12100E')
            css_content = css_content.replace('var(--light-bg)', '#FDFBF7')

    # 2. Buat QR Code Base64 untuk disisipkan langsung ke HTML
    verify_url = url_for('verify_certificate', token=art['encrypted_token'], _external=True)
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="#5C3A21", back_color="#FDFBF7")
    
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    today_str = datetime.now().strftime('%d %B %Y')

    # Render template HTML khusus cetak dengan injeksi CSS dan QR base64
    rendered_html = render_template(
        'preview.html',
        art=art,
        tgl_penerbitan=today_str,
        css_content=css_content,
        qr_base64=qr_base64,
        is_pdf=True
    )

    # 3. Compile HTML ke PDF menggunakan WeasyPrint dengan penanganan error
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=rendered_html).write_pdf()
        
        pdf_io = BytesIO(pdf_bytes)
        pdf_io.seek(0)
        
        filename = f"Sertifikat_{art['nama_karya'].replace(' ', '_')}.pdf"
        return send_file(
            pdf_io, 
            mimetype='application/pdf', 
            as_attachment=True, 
            download_name=filename
        )
    except Exception as e:
        # Jika WeasyPrint gagal (misal karena GTK+ tidak ada di Windows), lakukan fallback ke xhtml2pdf secara transparan!
        try:
            from xhtml2pdf import pisa
            pdf_io = BytesIO()
            pisa_status = pisa.CreatePDF(src=rendered_html, dest=pdf_io)
            if not pisa_status.err:
                pdf_io.seek(0)
                filename = f"Sertifikat_{art['nama_karya'].replace(' ', '_')}.pdf"
                return send_file(
                    pdf_io, 
                    mimetype='application/pdf', 
                    as_attachment=True, 
                    download_name=filename
                )
            else:
                raise Exception("xhtml2pdf failed to render PDF.")
        except Exception as fallback_err:
            # Mengembalikan error ke browser jika semua metode gagal
            flash(
                f"Gagal mengunduh PDF: WeasyPrint mendeteksi masalah sistem (GTK+ Library belum terpasang di Windows). "
                f"Percobaan fallback xhtml2pdf juga gagal. Error: {str(fallback_err)}", 
                "error"
            )
            return redirect(url_for('preview_certificate', art_id=art_id))


# ROUTE: GET /verify/<token>
# Halaman verifikasi keaslian karya batik berbasis One-Time Verification
@app.route('/verify/<token>')
def verify_certificate(token):
    # Dekripsi parameter token (encrypted_token) untuk mendapatkan token plaintext asli
    fernet = get_fernet_cipher()
    plaintext_token = None
    
    try:
        decrypted_bytes = fernet.decrypt(token.encode('utf-8'))
        plaintext_token = decrypted_bytes.decode('utf-8')
    except Exception:
        # Jika dekripsi gagal (misal link dirusak atau key berubah)
        return render_template('verify.html', success=False, art=None)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Cari token verifikasi di database
    cursor.execute('SELECT * FROM verification_tokens WHERE token = ?', (plaintext_token,))
    token_row = cursor.fetchone()

    if not token_row:
        conn.close()
        return render_template('verify.html', success=False, art=None)

    used = token_row['used']
    
    # Temukan karya batik yang memiliki encrypted_token ini
    # Lakukan pencarian dengan membandingkan token plaintext hasil dekripsi dari setiap baris
    cursor.execute('SELECT * FROM artworks')
    all_artworks = cursor.fetchall()
    
    matched_art = None
    for art in all_artworks:
        try:
            dec_bytes = fernet.decrypt(art['encrypted_token'].encode('utf-8'))
            dec_token = dec_bytes.decode('utf-8')
            if dec_token == plaintext_token:
                matched_art = dict(art)
                break
        except Exception:
            continue

    if used == 0:
        # One-Time Verification: Ubah status token menjadi 1 (used) saat pemindaian pertama kali
        cursor.execute(
            'UPDATE verification_tokens SET used = 1 WHERE token = ?',
            (plaintext_token,)
        )
        conn.commit()
        conn.close()
        
        # Kirim hasil sukses verifikasi
        return render_template('verify.html', success=True, art=matched_art)
    else:
        conn.close()
        # QR Code sudah pernah digunakan, tolak verifikasi
        return render_template('verify.html', success=False, art=matched_art)


if __name__ == '__main__':
    # Pastikan database telah diinisialisasi sebelum server berjalan
    # Menguji keberadaan database
    if not os.path.exists(DB_PATH):
        print("Database belum terdeteksi. Silakan jalankan 'python init_db.py' terlebih dahulu.")
    
    app.run(debug=True, port=5005)
