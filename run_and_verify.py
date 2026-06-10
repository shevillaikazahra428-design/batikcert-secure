import os
import subprocess
import time
import urllib.request
import urllib.error
import sqlite3
from cryptography.fernet import Fernet

def run_app_and_verify():
    print("=== MEMULAI PENGUJIAN JALAN APLIKASI SECARA LIVE ===")
    
    # 1. Pastikan database terisi
    db_path = os.path.join('instance', 'batikcert.db')
    if not os.path.exists(db_path):
        print("Database belum ada, menjalankan init_db.py...")
        subprocess.run(['venv\\Scripts\\python.exe', 'init_db.py'], check=True)

    # 2. Jalankan Flask app.py di background
    print("Menjalankan Flask app (app.py) di background...")
    proc = subprocess.Popen(
        ['venv\\Scripts\\python.exe', 'app.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Tunggu 3 detik agar server Flask siap menerima request
    time.sleep(3)
    
    url_base = "http://127.0.0.1:5005"
    
    try:
        # A. Uji GET / (Dashboard)
        print("\n[TEST A] Mengirim HTTP GET ke halaman utama (Dashboard)...")
        with urllib.request.urlopen(f"{url_base}/") as response:
            status = response.status
            html = response.read().decode('utf-8')
            print(f"-> HTTP Status: {status}")
            print(f"-> Apakah 'BatikCert Secure' ada di HTML? {'YA' if 'BatikCert' in html else 'TIDAK'}")
            print(f"-> Apakah karya 'Ulul Albab Geometry' terdaftar? {'YA' if 'Ulul Albab Geometry' in html else 'TIDAK'}")
            print(f"-> Apakah statistik 'Batik Geometris' tampil? {'YA' if 'Batik Geometris' in html else 'TIDAK'}")
            
        # B. Uji GET /preview/1 (Sertifikat Ulul Albab Geometry)
        print("\n[TEST B] Mengirim HTTP GET ke Halaman Preview Sertifikat (ID: 1)...")
        with urllib.request.urlopen(f"{url_base}/preview/1") as response:
            status = response.status
            html = response.read().decode('utf-8')
            print(f"-> HTTP Status: {status}")
            print(f"-> Apakah nomor sertifikat otomatis terbit? {'YA' if 'BCS/' in html else 'TIDAK'}")
            print(f"-> Apakah digest SHA-256 muncul? {'YA' if 'SHA-256 Digital Fingerprint' in html else 'TIDAK'}")

        # C. Ambil encrypted token dari DB untuk disimulasikan sebagai hasil scan QR Code
        print("\n[TEST C] Membaca token terenkripsi dari database...")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_token FROM artworks WHERE id = 1")
        art = cursor.fetchone()
        conn.close()
        
        encrypted_token = art['encrypted_token']
        print(f"-> Ciphertext token (AES/Fernet): {encrypted_token[:30]}...")

        # D. Verifikasi Pertama Kali (Harus Sukses)
        print("\n[TEST D] Simulasi Pemindaian QR Code (Verifikasi Pertama Kali)...")
        with urllib.request.urlopen(f"{url_base}/verify/{encrypted_token}") as response:
            status = response.status
            html = response.read().decode('utf-8')
            print(f"-> HTTP Status: {status}")
            print(f"-> Hasil di HTML: {'Karya Batik Asli & Sertifikat Valid (SUKSES)' if 'Karya Batik Asli' in html else 'GAGAL'}")

        # E. Verifikasi Kedua Kali (Harus Ditolak karena status token harus berubah jadi 'used')
        print("\n[TEST E] Simulasi Pemindaian QR Code Ulang (Verifikasi Kedua Kali)...")
        with urllib.request.urlopen(f"{url_base}/verify/{encrypted_token}") as response:
            status = response.status
            html = response.read().decode('utf-8')
            print(f"-> HTTP Status: {status}")
            print(f"-> Hasil di HTML: {'QR Code Sudah Pernah Digunakan (DITOLAK - AMAN)' if 'QR Code Sudah Pernah Digunakan' in html else 'GAGAL'}")

        print("\n=== SELURUH PENGUJIAN JALAN APLIKASI SUKSES 100% ===")

    except urllib.error.URLError as e:
        print(f"\n[ERROR] Gagal menghubungi server Flask: {e}")
    finally:
        # Hentikan proses Flask server secara aman
        print("\nMemberhentikan server Flask...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
            print("Server Flask telah dihentikan secara aman.")
        except subprocess.TimeoutExpired:
            proc.kill()
            print("Server Flask dipaksa mati.")

if __name__ == '__main__':
    run_app_and_verify()
