import os
import unittest
import sqlite3
import hashlib
from cryptography.fernet import Fernet

from app import app, DB_PATH, KEY_PATH, get_db_connection, get_fernet_cipher, calculate_sha256

class BatikCertSecureTestCase(unittest.TestCase):
    def setUp(self):
        # Konfigurasi Flask app untuk pengujian
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        # Reset database agar bersih sebelum setiap pengujian dijalankan
        if os.path.exists(DB_PATH):
            try:
                os.remove(DB_PATH)
            except OSError:
                pass
        
        # Jalankan fungsi inisialisasi database
        from init_db import main as init_db_main
        init_db_main()

        self.assertTrue(os.path.exists(DB_PATH))
        self.assertTrue(os.path.exists(KEY_PATH))

    def test_1_dashboard(self):
        """Uji halaman utama, muatan data awal, dan statistik"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        # Cek apakah judul aplikasi ada
        html = response.data.decode('utf-8')
        self.assertIn('BatikCert Secure', html)
        
        # Cek data awal
        self.assertIn('Ulul Albab Geometry', html)
        self.assertIn('Arabesque Harmony', html)
        self.assertIn('Fractal Blossom', html)
        self.assertIn('Shevilla', html)
        
        # Cek kategori statistik
        self.assertIn('Batik Geometris', html)
        self.assertIn('Batik Islami', html)
        self.assertIn('Batik Fraktal', html)

    def test_2_tambah_dan_verifikasi_karya(self):
        """Uji registrasi karya baru, pembuatan QR, dan alur verifikasi satu kali"""
        # 1. Tambah karya baru
        payload = {
            'nama_karya': 'Mega Mendung Digital',
            'desainer': 'Budi Pekerti',
            'tanggal_dibuat': '2026-06-10',
            'kategori': 'Lainnya',
            'custom_kategori': 'Batik Pesisir'
        }
        response = self.client.post('/tambah', data=payload, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        html = response.data.decode('utf-8')
        self.assertIn('Mega Mendung Digital', html)
        self.assertIn('Batik Pesisir', html)

        # Ambil data dari database untuk mengambil encrypted_token
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM artworks WHERE nama_karya = 'Mega Mendung Digital'")
        art = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(art)
        self.assertEqual(art['kategori'], 'Batik Pesisir')
        
        # Validasi SHA-256 digest
        expected_digest = calculate_sha256('Mega Mendung Digital', 'Budi Pekerti', '2026-06-10', 'Batik Pesisir')
        self.assertEqual(art['digest_sha256'], expected_digest)
        
        encrypted_token = art['encrypted_token']
        
        # 2. Uji QR Code route
        qr_response = self.client.get(f'/qrcode/{encrypted_token}')
        self.assertEqual(qr_response.status_code, 200)
        self.assertEqual(qr_response.mimetype, 'image/png')
        
        # 3. Uji preview sertifikat
        preview_response = self.client.get(f"/preview/{art['id']}")
        self.assertEqual(preview_response.status_code, 200)
        preview_html = preview_response.data.decode('utf-8')
        self.assertIn('Mega Mendung Digital', preview_html)
        self.assertIn(expected_digest, preview_html)

        # 4. Verifikasi Pertama Kali (Harus Sukses)
        verify_response = self.client.get(f'/verify/{encrypted_token}')
        self.assertEqual(verify_response.status_code, 200)
        verify_html = verify_response.data.decode('utf-8')
        
        # Cek kata kunci sukses sesuai spesifikasi
        self.assertIn('Karya Batik Asli', verify_html)
        self.assertIn('Sertifikat Valid', verify_html)
        
        # 5. Verifikasi Kedua Kali (Harus Ditolak / Used)
        verify_again_response = self.client.get(f'/verify/{encrypted_token}')
        self.assertEqual(verify_again_response.status_code, 200)
        verify_again_html = verify_again_response.data.decode('utf-8')
        
        # Cek kata kunci penolakan sesuai spesifikasi
        self.assertIn('QR Code Sudah Pernah Digunakan', verify_again_html)
        self.assertIn('Verifikasi Ditolak', verify_again_html)

    def test_3_edit_karya(self):
        """Uji modul edit dan pembaharuan SHA-256 digest"""
        # Ambil data Ulul Albab Geometry
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM artworks WHERE nama_karya = 'Ulul Albab Geometry'")
        art_id = cursor.fetchone()['id']
        conn.close()

        # Update data
        payload = {
            'nama_karya': 'Ulul Albab Geometry Premium',
            'desainer': 'Shevilla',
            'tanggal_dibuat': '2026-01-10',
            'kategori': 'Batik Geometris',
            'custom_kategori': ''
        }
        response = self.client.post(f'/edit/{art_id}', data=payload, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        html = response.data.decode('utf-8')
        self.assertIn('Ulul Albab Geometry Premium', html)
        
        # Verifikasi digest diperbaharui di database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT digest_sha256 FROM artworks WHERE id = ?", (art_id,))
        updated_art = cursor.fetchone()
        conn.close()
        
        expected_digest = calculate_sha256('Ulul Albab Geometry Premium', 'Shevilla', '2026-01-10', 'Batik Geometris')
        self.assertEqual(updated_art['digest_sha256'], expected_digest)

    def test_4_hapus_karya(self):
        """Uji penghapusan karya dan pembersihan token verifikasinya"""
        # Tambah karya dummy untuk dihapus
        payload = {
            'nama_karya': 'Karya Terhapus',
            'desainer': 'Anonim',
            'tanggal_dibuat': '2026-06-10',
            'kategori': 'Batik Islami',
            'custom_kategori': ''
        }
        self.client.post('/tambah', data=payload, follow_redirects=True)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, encrypted_token FROM artworks WHERE nama_karya = 'Karya Terhapus'")
        art = cursor.fetchone()
        art_id = art['id']
        encrypted_token = art['encrypted_token']
        conn.close()
        
        # Hapus karya
        response = self.client.post(f'/hapus/{art_id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Cek di database apakah data terhapus
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM artworks WHERE id = ?", (art_id,))
        art_count = cursor.fetchone()[0]
        
        # Cek apakah token verifikasi terhapus
        fernet = get_fernet_cipher()
        dec_bytes = fernet.decrypt(encrypted_token.encode('utf-8'))
        plaintext_token = dec_token = dec_bytes.decode('utf-8')
        cursor.execute("SELECT COUNT(*) FROM verification_tokens WHERE token = ?", (plaintext_token,))
        token_count = cursor.fetchone()[0]
        conn.close()
        
        self.assertEqual(art_count, 0)
        self.assertEqual(token_count, 0)

    def test_5_download_pdf_success_with_fallback(self):
        """Uji apakah fallback PDF (xhtml2pdf) menghasilkan PDF dengan sukses"""
        # Ambil ID karya yang ada
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM artworks LIMIT 1")
        art_id = cursor.fetchone()['id']
        conn.close()

        # Unduh PDF, harus berhasil mengembalikan file PDF (mimetype application/pdf)
        response = self.client.get(f'/download-pdf/{art_id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')

if __name__ == '__main__':
    unittest.main()
