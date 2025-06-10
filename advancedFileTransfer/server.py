#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Secure File Transfer Server
Bilgisayar Ağları Dönem Projesi - Server Component
"""

#...
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send, sniff
import random
from scapy.packet import Raw
import socket
import threading
import os
import json
import hashlib
import time
import struct
from datetime import datetime
from scapy.all import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class SecureFileTransferServer:
    def __init__(self, host='localhost', port=8080, password='secure123'):
        self.host = host
        self.port = port
        self.password = password
        self.running = False
        self.clients = {}
        self.server_socket = None
        
        # Güvenlik
        self.private_key = None
        self.public_key = None
        self.load_rsa_keys()
        
        # Performans metrikleri
        self.stats = {
            'connections': 0,
            'files_received': 0,
            'bytes_transferred': 0,
            'start_time': time.time()
        }
        
        # Dosya kayıt dizini
        self.upload_dir = "uploads"
        os.makedirs(self.upload_dir, exist_ok=True)
        
        print(f"🚀 Secure File Transfer Server başlatılıyor...")
        print(f"📡 Sunucu: {self.host}:{self.port}")
        print(f"🔐 Güvenlik: RSA + AES şifreleme")
        print(f"📁 Upload dizini: {self.upload_dir}")

    def load_rsa_keys(self):
        """RSA anahtarlarını yükle"""
        try:
            # Private key yükle
            with open('private_key.pem', 'rb') as f:
                self.private_key = RSA.import_key(f.read())
            
            # Public key yükle
            with open('public_key.pem', 'rb') as f:
                self.public_key = RSA.import_key(f.read())
                
            print(f"🔑 RSA anahtarları yüklendi ({self.private_key.size_in_bits()} bit)")
            
        except FileNotFoundError:
            print("❌ RSA anahtar dosyaları bulunamadı!")
            print("🔧 Önce generate_rsa_keys.py çalıştırın")
            exit(1)
        except Exception as e:
            print(f"❌ RSA anahtar yükleme hatası: {e}")
            exit(1)

    def create_custom_ip_packet(self, data, dest_ip):
        """
        Manuel IP paketi oluştur (Low-level IP processing)
        """
        try:
            # IP Header alanları
            ip_packet = IP(
                dst=dest_ip,
                ttl=64,  # Manuel TTL ayarı
                flags="DF",  # Don't Fragment flag
                frag=0,  # Fragmentation offset
                proto=socket.IPPROTO_TCP
            )
            
            # TCP Header
            tcp_packet = TCP(
                dport=self.port,
                sport=RandShort(),
                flags="PA",  # Push + Ack
                seq=RandInt(),
                ack=RandInt()
            )
            
            # Tam paket
            packet = ip_packet / tcp_packet / Raw(data)
            
            # Checksum hesapla
            packet = packet.__class__(bytes(packet))
            
            return packet
            
        except Exception as e:
            print(f"❌ IP paketi oluşturma hatası: {e}")
            return None

    def calculate_ip_checksum(self, packet_data):
        """
        IP Header checksum hesapla
        """
        try:
            # Checksum hesaplama
            checksum = 0
            for i in range(0, len(packet_data), 2):
                if i + 1 < len(packet_data):
                    word = (packet_data[i] << 8) + packet_data[i + 1]
                else:
                    word = packet_data[i] << 8
                checksum += word
            
            # Carry bitlerini ekle
            checksum = (checksum >> 16) + (checksum & 0xFFFF)
            checksum += (checksum >> 16)
            
            # One's complement
            checksum = ~checksum & 0xFFFF
            
            return checksum
            
        except Exception as e:
            print(f"❌ Checksum hesaplama hatası: {e}")
            return 0
    def udp_fragment_receiver_socket(self, port=8888):
        print("🛡️ [UDP SOCKET] Fragment receiver başlatıldı (UDP port 8888)")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', port))
        fragments = {}
        total = None
        sock.settimeout(20)
        start = time.time()
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                if len(data) >= 8:
                    idx, total_frag = struct.unpack("!I I", data[:8])
                    frag_data = data[8:]
                    fragments[idx] = frag_data
                    total = total_frag
                    print(f"🟢 Fragment alındı: {idx+1}/{total}")
                if total and len(fragments) == total:
                    break
            except socket.timeout:
                print("⏱️ Timeout, receiver kapanıyor.")
                break
            if time.time() - start > 30:  # 30 saniye sonra bırak
                print("⏱️ Süre doldu.")
                break
        sock.close()
        if total and len(fragments) == total:
            file_data = b''.join(fragments[i] for i in range(total))
            path = os.path.join(self.upload_dir, f"received_{int(time.time())}.bin")
            with open(path, "wb") as f:
                f.write(file_data)
            print(f"✅ Fragment dosyası başarıyla birleştirildi ve kaydedildi: {path}")
        else:
            print(f"❗ Fragment transferi tamamlanamadı veya eksik paket var. Gelen: {len(fragments)}/{total}")


    def start_fragment_receiver_minimal(self):
        print("UDP 8888 dinleniyor...")
        fragments = {}
        total = None
        def process(pkt):
            print("Paket geldi: ", pkt.summary())
            nonlocal total
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                idx, total_frag = struct.unpack("!I I", payload[:8])
                fragments[idx] = payload[8:]
                total = total_frag
                print(f"Fragment {idx+1}/{total_frag}")
        sniff(filter="udp and port 8888", prn=process, timeout=20)
        if total and len(fragments) == total:
            file_data = b''.join([fragments[i] for i in range(total)])
            filename = os.path.join(self.upload_dir, f"scapy_{int(time.time())}.bin")
            with open(filename, "wb") as f:
                f.write(file_data)
            print(f"==> Fragment dosya kaydedildi: {filename}")
        else:
            print("Fragment eksik!")

    # Not: uploads klasörü yoksa:
    # os.makedirs(self.upload_dir, exist_ok=True)
    def handle_fragmentation(self, data, mtu=1500):
        """
        Manuel paket fragmentasyonu
        """
        fragments = []
        header_size = 20  # IP header boyutu
        max_payload = mtu - header_size
        
        # Veriyi parçalara böl
        offset = 0
        while offset < len(data):
            fragment_data = data[offset:offset + max_payload]
            
            # Fragment bilgisi
            fragment_info = {
                'data': fragment_data,
                'offset': offset // 8,  # 8-byte units
                'more_fragments': offset + max_payload < len(data),
                'size': len(fragment_data)
            }
            
            fragments.append(fragment_info)
            offset += max_payload
        
        print(f"📦 Veri {len(fragments)} parçaya bölündü")
        return fragments

    def authenticate_client(self, client_socket, client_address):
        """
        İstemci kimlik doğrulaması
        """
        try:
            print(f"🔐 Kimlik doğrulaması başlıyor: {client_address}")
            
            # Şifreli parola bekle
            encrypted_password = client_socket.recv(256)
            
            if not encrypted_password:
                print(f"❌ Parola alınamadı: {client_address}")
                return False
            
            # RSA ile şifre çöz
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            decrypted_password = cipher_rsa.decrypt(encrypted_password).decode('utf-8')
            
            # Parola doğrula
            if decrypted_password == self.password:
                print(f"✅ Kimlik doğrulaması başarılı: {client_address}")
                client_socket.send(b"AUTH_SUCCESS")
                return True
            else:
                print(f"❌ Yanlış parola: {client_address}")
                client_socket.send(b"AUTH_FAILED")
                return False
                
        except Exception as e:
            print(f"❌ Kimlik doğrulama hatası: {e}")
            client_socket.send(b"AUTH_ERROR")
            return False

    def receive_aes_key(self, client_socket):
        """
        İstemciden AES anahtarını al
        """
        try:
            # Şifreli AES anahtarı ve IV al
            encrypted_key_data = client_socket.recv(512)
            
            if not encrypted_key_data:
                return None, None
            
            # RSA ile şifre çöz
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            decrypted_data = cipher_rsa.decrypt(encrypted_key_data)
            
            # Anahtar ve IV'yi ayır
            aes_key = decrypted_data[:32]  # 256-bit AES anahtarı
            aes_iv = decrypted_data[32:48]  # 128-bit IV
            
            print("🔑 AES oturum anahtarı alındı")
            return aes_key, aes_iv
            
        except Exception as e:
            print(f"❌ AES anahtar alma hatası: {e}")
            return None, None

    def decrypt_aes_data(self, encrypted_data, aes_key, aes_iv):
        """
        AES ile veri şifresi çöz
        """
        try:
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
            return decrypted_data
        except Exception as e:
            print(f"❌ AES şifre çözme hatası: {e}")
            return None

    def verify_file_integrity(self, file_data, received_hash):
        """
        Dosya bütünlüğünü SHA-256 ile doğrula
        """
        calculated_hash = hashlib.sha256(file_data).hexdigest()
        
        if calculated_hash == received_hash:
            print("✅ Dosya bütünlüğü doğrulandı")
            return True
        else:
            print("❌ Dosya bütünlüğü hatası!")
            print(f"Hesaplanan: {calculated_hash}")
            print(f"Alınan: {received_hash}")
            return False

    def handle_client(self, client_socket, client_address):
        """
        İstemci bağlantısını işle
        """
        try:
            print(f"🔗 Yeni bağlantı: {client_address}")
            self.stats['connections'] += 1
            
            # Manuel TCP handshake yanıtı
            client_socket.send(b"TCP_HANDSHAKE_ACK")
            
            # AES oturum anahtarını al
            aes_key, aes_iv = self.receive_aes_key(client_socket)
            if not aes_key or not aes_iv:
                print("❌ AES anahtar alınamadı")
                return
            
            # Kimlik doğrulaması
            if not self.authenticate_client(client_socket, client_address):
                return
            
            # İstemci bilgilerini kaydet
            self.clients[client_address] = {
                'socket': client_socket,
                'aes_key': aes_key,
                'aes_iv': aes_iv,
                'authenticated': True,
                'connected_at': time.time()
            }
            
            print(f"✅ İstemci hazır: {client_address}")
            
            # Dosya transferi işlemleri
            while True:
                try:
                    # Komut bekle
                    command = client_socket.recv(1024).decode('utf-8')
                    
                    if not command:
                        break
                    
                    if command == "SEND_FILE":
                        self.receive_file(client_socket, client_address, aes_key, aes_iv)
                    elif command == "LIST_FILES":
                        self.send_file_list(client_socket)
                    elif command == "DISCONNECT":
                        print(f"🔌 İstemci ayrılıyor: {client_address}")
                        break
                    else:
                        print(f"❓ Bilinmeyen komut: {command}")
                        
                except ConnectionResetError:
                    print(f"🔌 Bağlantı kesildi: {client_address}")
                    break
                except Exception as e:
                    print(f"❌ İstemci işleme hatası: {e}")
                    break
            
        except Exception as e:
            print(f"❌ İstemci bağlantı hatası: {e}")
        finally:
            # Temizlik
            if client_address in self.clients:
                del self.clients[client_address]
            client_socket.close()
            print(f"🔌 Bağlantı kapatıldı: {client_address}")

    def receive_file(self, client_socket, client_address, aes_key, aes_iv):
        """
        Şifrelenmiş dosya al (fragmented TCP!)
        """
        try:
            print(f"📥 Dosya alınıyor: {client_address}")

            # Dosya bilgilerini al
            file_info = client_socket.recv(1024).decode('utf-8')
            filename, file_size, file_hash, fragment_size = file_info.split('|')
            file_size = int(file_size)
            fragment_size = int(fragment_size)

            print(f"📄 Dosya: {filename} ({file_size} bytes, {fragment_size} fragment size)")

            # Kaç fragment bekleyeceğini hesapla
            total_fragments = (file_size + fragment_size - 1) // fragment_size

            fragments = [None] * total_fragments
            received = 0

            while received < total_fragments:
                # Header: index(4), datalen(4)
                header = b''
                while len(header) < 8:
                    chunk = client_socket.recv(8 - len(header))
                    if not chunk:
                        break
                    header += chunk
                if len(header) < 8:
                    print("❌ Header eksik geldi, bağlantı kesildi.")
                    break
                idx, datalen = struct.unpack("!II", header)
                # Data
                data = b''
                while len(data) < datalen:
                    chunk = client_socket.recv(datalen - len(data))
                    if not chunk:
                        break
                    data += chunk
                if len(data) != datalen:
                    print("❌ Fragment eksik geldi.")
                    break
                fragments[idx] = data
                received += 1
                print(f"\r📦 Fragment {idx+1}/{total_fragments} alındı.", end='')

            print()
            if None in fragments:
                print("❌ Bütün fragmentler alınamadı!")
                client_socket.send(b"FILE_RECEIVE_ERROR")
                return

            # Tüm fragmentleri birleştir
            encrypted_data = b''.join(fragments)
            print(f"🔓 Tüm fragmentler birleştirildi, {len(encrypted_data)} byte")

            # AES şifresi çöz
            decrypted_data = self.decrypt_aes_data(encrypted_data, aes_key, aes_iv)
            if decrypted_data is None:
                print("❌ Dosya şifresi çözülemedi")
                client_socket.send(b"FILE_DECRYPT_ERROR")
                return

            # Dosya bütünlüğünü doğrula
            if not self.verify_file_integrity(decrypted_data, file_hash):
                print("❌ Dosya bütünlüğü doğrulanamadı")
                client_socket.send(b"FILE_INTEGRITY_ERROR")
                return

            # Dosyayı kaydet
            safe_filename = os.path.basename(filename)
            filepath = os.path.join(self.upload_dir, safe_filename)
            with open(filepath, 'wb') as f:
                f.write(decrypted_data)

            print(f"✅ Dosya kaydedildi: {filepath}")
            self.stats['files_received'] += 1
            self.stats['bytes_transferred'] += file_size
            client_socket.send(b"FILE_RECEIVED_SUCCESS")

        except Exception as e:
            print(f"❌ Dosya alma hatası: {e}")
            client_socket.send(b"FILE_RECEIVE_ERROR")
        """
        Sunucudaki dosya listesini gönder
        """
        try:
            files = os.listdir(self.upload_dir)
            file_list = []
            
            for filename in files:
                filepath = os.path.join(self.upload_dir, filename)
                if os.path.isfile(filepath):
                    file_size = os.path.getsize(filepath)
                    file_list.append(f"{filename}|{file_size}")
            
            response = '\n'.join(file_list)
            client_socket.send(response.encode('utf-8'))
            
        except Exception as e:
            print(f"❌ Dosya listesi gönderme hatası: {e}")
            client_socket.send(b"FILE_LIST_ERROR")

    def show_stats(self):
        """
        Sunucu istatistiklerini göster
        """
        uptime = time.time() - self.stats['start_time']
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        
        print(f"\n📊 SUNUCU İSTATİSTİKLERİ")
        print(f"🕐 Çalışma süresi: {hours:02d}:{minutes:02d}:{seconds:02d}")
        print(f"🔗 Toplam bağlantı: {self.stats['connections']}")
        print(f"📁 Alınan dosya: {self.stats['files_received']}")
        print(f"📊 Transfer edilen: {self.stats['bytes_transferred']} bytes")
        print(f"👥 Aktif istemci: {len(self.clients)}")

    def start_server(self):
        """
        Sunucuyu başlat
        """
        # start_server fonksiyonunun hemen başında:
        # self.start_fragment_receiver yerine:
        threading.Thread(target=self.udp_fragment_receiver_socket, daemon=True).start()
 

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            print(f"🚀 Sunucu başlatıldı: {self.host}:{self.port}")
            print("📡 İstemci bağlantıları bekleniyor...")
            print("🔴 Durdurmak için Ctrl+C basın\n")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Her istemci için ayrı thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    print("\n🛑 Sunucu kapatılıyor...")
                    self.running = False
                    break
                except Exception as e:
                    if self.running:
                        print(f"❌ Sunucu hatası: {e}")
                    
        except Exception as e:
            print(f"❌ Sunucu başlatma hatası: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        """
        Sunucu temizliği
        """
        self.running = False
        
        # Tüm istemci bağlantılarını kapat
        for client_info in self.clients.values():
            try:
                client_info['socket'].close()
            except:
                pass
        
        # Sunucu socket'ini kapat
        if self.server_socket:
            self.server_socket.close()
        
        self.show_stats()
        print("👋 Sunucu kapatıldı")

def main():
    """
    Ana fonksiyon
    """
    print("=== ADVANCED SECURE FILE TRANSFER SERVER ===")
    print("Bilgisayar Ağları Dönem Projesi\n")
    
    # Konfigürasyon dosyasını kontrol et
    config_file = "server_config.json"
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            host = config.get('server', {}).get('host', 'localhost')
            port = config.get('server', {}).get('port', 8080)
            password = config.get('server', {}).get('password', 'secure123')
            
            print(f"📋 Konfigürasyon yüklendi: {config_file}")
            
        except Exception as e:
            print(f"❌ Konfigürasyon hatası: {e}")
            print("🔧 Varsayılan ayarlar kullanılıyor")
            host, port, password = 'localhost', 8080, 'secure123'
    else:
        host, port, password = 'localhost', 8080, 'secure123'
        print("⚠️  Konfigürasyon dosyası bulunamadı, varsayılan ayarlar kullanılıyor")
    
    # Sunucuyu başlat
    server = SecureFileTransferServer(host, port, password)
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Sunucu durduruldu")
    except Exception as e:
        print(f"❌ Sunucu hatası: {e}")

if __name__ == "__main__":
    main()