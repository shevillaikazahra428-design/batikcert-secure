import os
import sqlite3
import hashlib
import secrets
from cryptography.fernet import Fernet

def get_db_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def main():
    # Definisikan path folder instance dan database
    base_dir = os.path.dirname(os.path.abspath(__file__))
    instance_dir = os.path.join(base_dir, 'instance')
    db_path = os.path.join(instance_dir, 'batikcert.db')
    key_path = os.path.join(instance_dir, 'secret.key')

    # Buat folder instance jika belum ada
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)
        print(f"Folder instance berhasil dibuat di: {instance_dir}")

    # Generate atau baca Fernet key
    env_key = os.environ.get('FERNET_SECRET_KEY')
    if env_key:
        key = env_key.encode('utf-8')
        print("Kunci enkripsi Fernet dimuat dari environment variable.")
    else:
        if not os.path.exists(key_path):
            key = Fernet.generate_key()
            with open(key_path, 'wb') as key_file:
                key_file.write(key)
            print("Kunci enkripsi Fernet (secret.key) berhasil dibuat.")
        else:
            with open(key_path, 'rb') as key_file:
                key = key_file.read()
            print("Kunci enkripsi Fernet ditemukan.")

    fernet = Fernet(key)

    # Hubungkan ke database SQLite
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Buat tabel artworks
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS artworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama_karya TEXT NOT NULL,
            desainer TEXT NOT NULL,
            tanggal_dibuat TEXT NOT NULL,
            kategori TEXT NOT NULL,
            digest_sha256 TEXT NOT NULL,
            encrypted_token TEXT NOT NULL
        )
    ''')

    # Buat tabel verification_tokens
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Komitmen perubahan tabel
    conn.commit()
    print("Tabel database berhasil dibuat/diverifikasi.")

    # Cek apakah sudah ada data awal
    cursor.execute('SELECT COUNT(*) FROM artworks')
    count = cursor.fetchone()[0]

    if count == 0:
        # Data awal yang diminta
        initial_artworks = [
            {
                "nama_karya": "Ulul Albab Geometry",
                "desainer": "Shevilla",
                "tanggal_dibuat": "2026-01-10",
                "kategori": "Batik Geometris"
            },
            {
                "nama_karya": "Arabesque Harmony",
                "desainer": "Shevilla",
                "tanggal_dibuat": "2026-02-15",
                "kategori": "Batik Islami"
            },
            {
                "nama_karya": "Fractal Blossom",
                "desainer": "Shevilla",
                "tanggal_dibuat": "2026-03-20",
                "kategori": "Batik Fraktal"
            }
        ]

        print("Memasukkan data awal...")
        for art in initial_artworks:
            nama = art["nama_karya"]
            desainer = art["desainer"]
            tanggal = art["tanggal_dibuat"]
            kategori = art["kategori"]

            # 1. SHA-256 digest dari: nama_karya|desainer|tanggal_dibuat|kategori
            raw_data = f"{nama}|{desainer}|{tanggal}|{kategori}"
            digest = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()

            # 2. Buat token verifikasi yang unik
            plaintext_token = secrets.token_urlsafe(32)

            # 3. Simpan token verifikasi ke database (status: used = 0)
            cursor.execute(
                'INSERT INTO verification_tokens (token, used) VALUES (?, ?)',
                (plaintext_token, 0)
            )

            # 4. Enkripsi token dengan Fernet (AES) untuk disimpan di artworks
            encrypted_token_bytes = fernet.encrypt(plaintext_token.encode('utf-8'))
            encrypted_token_str = encrypted_token_bytes.decode('utf-8')

            # 5. Masukkan data karya ke tabel artworks
            cursor.execute('''
                INSERT INTO artworks (nama_karya, desainer, tanggal_dibuat, kategori, digest_sha256, encrypted_token)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (nama, desainer, tanggal, kategori, digest, encrypted_token_str))

        conn.commit()
        print("Data awal berhasil dimasukkan!")
    else:
        print("Database sudah terisi data. Tidak perlu memasukkan data awal.")

    conn.close()
    print("Koneksi database ditutup. Inisialisasi selesai.")

if __name__ == '__main__':
    main()
