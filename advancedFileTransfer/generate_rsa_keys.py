#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSA Anahtar Çifti Üretici
Advanced Secure File Transfer System için RSA public/private key üretir
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import json

def generate_rsa_keypair(key_size=2048):
    """
    RSA anahtar çifti üretir
    Args:
        key_size (int): Anahtar boyutu (varsayılan: 2048)
    Returns:
        tuple: (private_key, public_key)
    """
    print(f"🔐 {key_size} bit RSA anahtar çifti üretiliyor...")
    
    # RSA anahtar çifti üret
    key = RSA.generate(key_size)
    
    # Private key
    private_key = key.export_key()
    
    # Public key
    public_key = key.publickey().export_key()
    
    return private_key, public_key

def save_keys_to_files(private_key, public_key, 
                      private_filename="private_key.pem", 
                      public_filename="public_key.pem"):
    """
    Anahtarları dosyalara kaydet
    Args:
        private_key: Private key bytes
        public_key: Public key bytes
        private_filename: Private key dosya adı
        public_filename: Public key dosya adı
    """
    
    # Private key kaydet
    with open(private_filename, 'wb') as f:
        f.write(private_key)
    print(f"🔑 Private key kaydedildi: {private_filename}")
    
    # Public key kaydet
    with open(public_filename, 'wb') as f:
        f.write(public_key)
    print(f"🔓 Public key kaydedildi: {public_filename}")
    
    # Dosya izinlerini güvenli yap (sadece owner okuyabilir)
    os.chmod(private_filename, 0o600)
    os.chmod(public_filename, 0o644)

def load_private_key(filename="private_key.pem"):
    """Private key dosyasından yükle"""
    try:
        with open(filename, 'rb') as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"❌ Private key dosyası bulunamadı: {filename}")
        return None
    except Exception as e:
        print(f"❌ Private key yükleme hatası: {e}")
        return None

def load_public_key(filename="public_key.pem"):
    """Public key dosyasından yükle"""
    try:
        with open(filename, 'rb') as f:
            return RSA.import_key(f.read())
    except FileNotFoundError:
        print(f"❌ Public key dosyası bulunamadı: {filename}")
        return None
    except Exception as e:
        print(f"❌ Public key yükleme hatası: {e}")
        return None

def test_rsa_encryption():
    """RSA şifreleme testini gerçekleştir"""
    print("\n🧪 RSA şifreleme testi başlıyor...")
    
    # Anahtarları yükle
    private_key = load_private_key()
    public_key = load_public_key()
    
    if not private_key or not public_key:
        print("❌ Test için anahtarlar yüklenemedi")
        return False
    
    try:
        # Test mesajı
        test_message = "Bu bir RSA test mesajıdır! 🔐"
        test_data = test_message.encode('utf-8')
        
        # Şifreleme
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher_rsa.encrypt(test_data)
        print(f"✅ Mesaj şifrelendi. Boyut: {len(encrypted_data)} bytes")
        
        # Şifre çözme
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(encrypted_data)
        decrypted_message = decrypted_data.decode('utf-8')
        
        print(f"✅ Mesaj çözüldü: {decrypted_message}")
        
        # Doğrulama
        if test_message == decrypted_message:
            print("✅ RSA şifreleme testi başarılı!")
            return True
        else:
            print("❌ RSA test başarısız - mesajlar eşleşmiyor")
            return False
            
    except Exception as e:
        print(f"❌ RSA test hatası: {e}")
        return False

def create_server_config():
    """Sunucu konfigürasyon dosyası oluştur"""
    config = {
        "server": {
            "host": "localhost",
            "port": 8080,
            "password": "secure123",
            "max_connections": 5,
            "buffer_size": 4096,
            "timeout": 30
        },
        "security": {
            "rsa_key_size": 2048,
            "aes_key_size": 32,
            "hash_algorithm": "SHA256",
            "private_key_file": "private_key.pem",
            "public_key_file": "public_key.pem"
        },
        "performance": {
            "chunk_size": 1024,
            "max_file_size": 104857600,  # 100MB
            "compression": True
        }
    }
    
    with open('server_config.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    
    print("📋 Sunucu konfigürasyonu oluşturuldu: server_config.json")

def main():
    """Ana fonksiyon"""
    print("=== RSA ANAHTAR YÖNETİCİSİ ===")
    print("Advanced Secure File Transfer System\n")
    
    while True:
        print("\nSeçenekler:")
        print("1. Yeni RSA anahtar çifti üret")
        print("2. Mevcut anahtarları test et")
        print("3. Sunucu konfigürasyonu oluştur")
        print("4. Anahtar bilgilerini göster")
        print("5. Çıkış")
        
        choice = input("\nSeçiminizi yapın (1-5): ").strip()
        
        if choice == '1':
            # Anahtar boyutu seç
            key_sizes = [1024, 2048, 3072, 4096]
            print("\nAnahtar boyutu seçin:")
            for i, size in enumerate(key_sizes, 1):
                print(f"{i}. {size} bit")
            
            size_choice = input("Seçim (varsayılan: 2048 bit): ").strip()
            
            if size_choice.isdigit() and 1 <= int(size_choice) <= 4:
                key_size = key_sizes[int(size_choice) - 1]
            else:
                key_size = 2048
            
            # Anahtarları üret
            private_key, public_key = generate_rsa_keypair(key_size)
            save_keys_to_files(private_key, public_key)
            
            print("✅ RSA anahtar çifti başarıyla oluşturuldu!")
            
        elif choice == '2':
            if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
                test_rsa_encryption()
            else:
                print("❌ Anahtar dosyaları bulunamadı. Önce anahtar üretin.")
                
        elif choice == '3':
            create_server_config()
            
        elif choice == '4':
            # Anahtar bilgilerini göster
            if os.path.exists("private_key.pem"):
                private_key = load_private_key()
                if private_key:
                    print(f"🔑 Private Key Boyutu: {private_key.size_in_bits()} bit")
                    print(f"📁 Private Key Dosyası: private_key.pem")
            
            if os.path.exists("public_key.pem"):
                public_key = load_public_key()
                if public_key:
                    print(f"🔓 Public Key Boyutu: {public_key.size_in_bits()} bit")
                    print(f"📁 Public Key Dosyası: public_key.pem")
                    
            if not os.path.exists("private_key.pem") and not os.path.exists("public_key.pem"):
                print("❌ Hiç anahtar dosyası bulunamadı")
                
        elif choice == '5':
            print("👋 Çıkış yapılıyor...")
            break
            
        else:
            print("❌ Geçersiz seçim")

if __name__ == "__main__":
    main()