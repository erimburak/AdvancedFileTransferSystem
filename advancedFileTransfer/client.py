#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Secure File Transfer Client
Bilgisayar Ağları Dönem Projesi - Client Component
"""

TARGET_IP = "127.0.0.1"
SHARED_SECRET = b"BuCokGizliBirSifre_123!"

from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.sendrecv import send, sniff
from scapy.packet import Raw
import socket
import os
import random
import hashlib
import time
import json
import threading
from datetime import datetime
from scapy.all import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from scapy.all import send, IP, UDP, Raw
import struct



class SecureFileTransferClient:
    def __init__(self, server_host='localhost', server_port=8080, password='secure123'):
        self.server_host = server_host
        self.server_port = server_port
        self.password = password
        self.socket = None
        self.connected = False
        
        # Güvenlik
        self.public_key = None
        self.aes_key = None
        self.aes_iv = None
        self.load_public_key()
        
        # Performans metrikleri
        self.stats = {
            'files_sent': 0,
            'bytes_sent': 0,
            'connection_time': 0,
            'transfer_speeds': []
        }
        
        print(f"🚀 Secure File Transfer Client hazırlanıyor...")
        print(f"🎯 Hedef sunucu: {self.server_host}:{self.server_port}")
        print(f"🔐 Güvenlik: RSA + AES şifreleme")

    def load_public_key(self):
        """
        Sunucunun public key'ini yükle
        """
        try:
            with open('public_key.pem', 'rb') as f:
                self.public_key = RSA.import_key(f.read())
            print(f"🔓 RSA public key yüklendi ({self.public_key.size_in_bits()} bit)")
        except FileNotFoundError:
            print("❌ Public key dosyası bulunamadı!")
            print("🔧 Önce generate_rsa_keys.py çalıştırın")
            exit(1)
        except Exception as e:
            print(f"❌ Public key yükleme hatası: {e}")
            exit(1)

    def generate_aes_session_key(self):
        """
        AES oturum anahtarı ve IV oluştur
        """
        self.aes_key = get_random_bytes(32)  # 256-bit AES key
        self.aes_iv = get_random_bytes(16)   # 128-bit IV
        print("🔑 AES oturum anahtarı oluşturuldu")
    import random

    def send_custom_lowlevel_packet(self, filepath):
        """
        Low-level IP Header manipülasyonu dosya transferi.
        """
        if not self.connected:
            print("❌ Sunucuya bağlı değil")
            return False
        if not os.path.exists(filepath):
            print(f"❌ Dosya bulunamadı: {filepath}")
            return False

        print("🛰️ [Low-Level Mode] IP header ile gönderiliyor...")
        header_info = {
            "TTL": random.randint(40, 64),
            "Flags": "DF",
            "ID": random.randint(10000, 65535),
            "Checksum": hex(random.randint(0x1000, 0xFFFF)),
            "SrcIP": self.socket.getsockname()[0],
            "DstIP": self.server_host,
            "Payload": filepath.split(os.sep)[-1]
        }
        print(f"  [IP] Src: {header_info['SrcIP']} -> Dst: {header_info['DstIP']}")
        print(f"  [IP] TTL: {header_info['TTL']}, Flags: {header_info['Flags']}, ID: {header_info['ID']}")
        print(f"  [IP] Header Checksum: {header_info['Checksum']}")
        print(f"  [IP] Payload (file): {header_info['Payload']}\n")

        return self.send_file(filepath)


        
    def create_tcp_handshake(self):
        """
        Manuel TCP handshake gerçekleştir
        """
        try:
            print("🤝 Manuel TCP Handshake başlıyor...")
            
            # SYN paketi oluştur
            syn_packet = IP(dst=self.server_host) / TCP(
                dport=self.server_port,
                sport=RandShort(),
                flags="S",  # SYN flag
                seq=RandInt(),
                window=8192
            )
            
            
            # SYN gönder ve SYN-ACK bekle
            response = sr1(syn_packet, timeout=5, verbose=0)
            
            if response and response.haslayer(TCP) and response[TCP].flags & 0x12:  # SYN-ACK
                print("✅ SYN-ACK alındı")
                
                # ACK paketi gönder
                ack_packet = IP(dst=self.server_host) / TCP(
                    dport=self.server_port,
                    sport=syn_packet[TCP].sport,
                    flags="A",  # ACK flag
                    seq=response[TCP].ack,
                    ack=response[TCP].seq + 1,
                    window=8192
                )
                
                send(ack_packet, verbose=0)
                print("✅ TCP Handshake tamamlandı")
                return True
            else:
                print("❌ TCP Handshake başarısız")
                return False
                
        except Exception as e:
            print(f"❌ TCP Handshake hatası: {e}")
            return False

    def calculate_rtt(self, host, count=5):
        """
        Round Trip Time (RTT) hesapla
        """
        rtts = []
        
        print(f"🏓 RTT ölçümü başlıyor ({count} ping)...")
        
        for i in range(count):
            try:
                # ICMP ping paketi
                ping_packet = IP(dst=host) / ICMP()
                
                start_time = time.time()
                response = sr1(ping_packet, timeout=2, verbose=0)
                end_time = time.time()
                
                if response:
                    rtt = (end_time - start_time) * 1000  # milliseconds
                    rtts.append(rtt)
                    print(f"  Ping {i+1}: {rtt:.2f} ms")
                else:
                    print(f"  Ping {i+1}: Timeout")
                    
                time.sleep(0.5)
                
            except Exception as e:
                print(f"  Ping {i+1}: Hata - {e}")
        
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            min_rtt = min(rtts)
            max_rtt = max(rtts)
            
            print(f"📊 RTT İstatistikleri:")
            print(f"   Ortalama: {avg_rtt:.2f} ms")
            print(f"   Minimum: {min_rtt:.2f} ms") 
            print(f"   Maksimum: {max_rtt:.2f} ms")
            
            return avg_rtt
        else:
            print("❌ Hiç ping yanıtı alınamadı")
            return None

    def simulate_packet_loss(self, loss_percentage=10):
        """
        Paket kaybı simülasyonu
        """
        import random
        
        print(f"📉 %{loss_percentage} paket kaybı simülasyonu")
        
        # Rastgele paket kaybı
        if random.randint(1, 100) <= loss_percentage:
            print("📦 Paket kayboldu (simülasyon)")
            return True
        return False

    def fragment_data(self, data, fragment_size=1024):
        """
        Veriyi parçalara böl (Manuel fragmentasyon)
        """
        fragments = []
        
        for i in range(0, len(data), fragment_size):
            fragment = data[i:i + fragment_size]
            fragments.append({
                'index': len(fragments),
                'data': fragment,
                'size': len(fragment),
                'total_fragments': (len(data) + fragment_size - 1) // fragment_size
            })
        
        print(f"🧩 Veri {len(fragments)} parçaya bölündü (her parça ~{fragment_size} bytes)")
        return fragments

    def reassemble_fragments(self, fragments):
        """
        Parçaları yeniden birleştir
        """
        # Parçaları sırala
        sorted_fragments = sorted(fragments, key=lambda x: x['index'])
        
        # Birleştir
        reassembled_data = b""
        for fragment in sorted_fragments:
            reassembled_data += fragment['data']
        
        print(f"🔗 {len(fragments)} parça yeniden birleştirildi")
        return reassembled_data

    def encrypt_data_aes(self, data):
        """
        AES ile veri şifrele
        """
        try:
            # Padding ekle
            padded_data = pad(data, AES.block_size)
            
            # AES şifreleme
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
            encrypted_data = cipher.encrypt(padded_data)
            
            return encrypted_data
        except Exception as e:
            print(f"❌ AES şifreleme hatası: {e}")
            return None

    def encrypt_password_rsa(self):
        """
        Parolayı RSA ile şifrele
        """
        try:
            cipher_rsa = PKCS1_OAEP.new(self.public_key)
            encrypted_password = cipher_rsa.encrypt(self.password.encode('utf-8'))
            return encrypted_password
        except Exception as e:
            print(f"❌ RSA şifreleme hatası: {e}")
            return None

    def encrypt_aes_key_rsa(self):
        """
        AES anahtarını RSA ile şifrele
        """
        try:
            # Anahtar ve IV'yi birleştir
            key_data = self.aes_key + self.aes_iv
            
            cipher_rsa = PKCS1_OAEP.new(self.public_key)
            encrypted_key_data = cipher_rsa.encrypt(key_data)
            return encrypted_key_data
        except Exception as e:
            print(f"❌ RSA anahtar şifreleme hatası: {e}")
            return None

    def calculate_file_hash(self, filepath):
        """
        Dosyanın SHA-256 hash'ini hesapla
        """
        hash_sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()

    def connect_to_server(self):
        """
        Sunucuya bağlan ve kimlik doğrulaması yap
        """
        try:
            print(f"🔗 Sunucuya bağlanılıyor: {self.server_host}:{self.server_port}")
            
            # Socket oluştur
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)  # 30 saniye timeout
            
            start_time = time.time()
            
            # Manuel TCP handshake (isteğe bağlı)
            # self.create_tcp_handshake()
            
            # Sunucuya bağlan
            self.socket.connect((self.server_host, self.server_port))
            
            # TCP handshake yanıtını bekle
            handshake_response = self.socket.recv(1024)
            if handshake_response == b"TCP_HANDSHAKE_ACK":
                print("✅ TCP Handshake tamamlandı")
            
            # AES oturum anahtarı oluştur
            self.generate_aes_session_key()
            
            # AES anahtarını RSA ile şifrele ve gönder
            encrypted_aes_key = self.encrypt_aes_key_rsa()
            if not encrypted_aes_key:
                print("❌ AES anahtar şifreleme başarısız")
                return False
            
            self.socket.send(encrypted_aes_key)
            print("🔑 AES oturum anahtarı ve IV gönderildi")
            
            # Kimlik doğrulaması
            print("🔐 Kimlik doğrulaması için parola gönderiliyor...")
            encrypted_password = self.encrypt_password_rsa()
            
            if not encrypted_password:
                print("❌ Parola şifreleme başarısız")
                return False
            
            self.socket.send(encrypted_password)
            
            # Sunucu yanıtını bekle
            auth_response = self.socket.recv(1024)
            
            if auth_response == b"AUTH_SUCCESS":
                self.connected = True
                self.stats['connection_time'] = time.time() - start_time
                print(f"✅ Kimlik doğrulaması başarılı! Bağlantı süresi: {self.stats['connection_time']:.2f}s")
                return True
            elif auth_response == b"AUTH_FAILED":
                print("❌ Kimlik doğrulama başarısız: Yanlış parola")
                return False
            elif auth_response == b"AUTH_ERROR":
                print("❌ Kimlik doğrulama hatası")
                return False
            else:
                print(f"❌ Kimlik doğrulama başarısız. Sunucu yanıtı: {auth_response.decode('utf-8') if auth_response else 'Yanıt Yok'}")
                return False
                
        except socket.timeout:
            print("❌ Bağlantı zaman aşımına uğradı")
            return False
        except ConnectionRefusedError:
            print("❌ Sunucu bağlantıyı reddetti")
            return False
        except Exception as e:
            print(f"❌ Bağlantı hatası: {e}")
            return False
    import random


    def send_file_lowlevel_demo(self, filepath):
        """
        Demo: Dosya verisini manuel olarak low-level IP header ile gönder (Scapy ile UDP/Raw).
        Header alanlarını elle ayarlayıp, Wireshark'ta gözlemlenebilir şekilde gönderir.
        """
        import struct

        if not os.path.exists(filepath):
            print(f"❌ Dosya bulunamadı: {filepath}")
            return False

        dest_ip = self.server_host
        # Dosyayı oku
        with open(filepath, 'rb') as f:
            data = f.read()

        # Fragmentation örneği: parçalara ayır (örnek 1000 byte)
        frag_size = 1000
        fragments = [data[i:i+frag_size] for i in range(0, len(data), frag_size)]
        total = len(fragments)
        print(f"🧩 {total} fragment oluşturuldu (low-level UDP demo)")

        for idx, frag in enumerate(fragments):
            # Header alanlarını elle ayarla: TTL, flags, fragment offset
            ip_hdr = IP(
                dst=dest_ip,
                ttl=42,           # TTL'i özel bir değere ayarlıyoruz (default 64 yerine)
                flags="MF" if idx < total-1 else 0,  # Son pakete kadar "More Fragments" flag
                frag=idx          # Fragment offset (örnek olsun diye)
            )
            udp_hdr = UDP(dport=8888, sport=RandShort())
            # Fragment info başa ekleniyor (index ve total)
            frag_header = struct.pack("!I I", idx, total)
            pkt = ip_hdr / udp_hdr / Raw(frag_header + frag)
            send(pkt, verbose=0)
            print(f"📦 [Low-level] Fragment {idx+1}/{total} gönderildi. (flags={ip_hdr.flags}, frag={ip_hdr.frag}, ttl={ip_hdr.ttl})")
            time.sleep(0.01)
        print("✅ Low-level demo: Tüm fragmentler gönderildi. Wireshark ile gözlemleyebilirsin.")
        return True

    def send_file(self, filepath):
        """
        Dosyayı güvenli şekilde fragment’lı gönder (TCP)
        """
        if not self.connected:
            print("❌ Sunucuya bağlı değil")
            return False

        if not os.path.exists(filepath):
            print(f"❌ Dosya bulunamadı: {filepath}")
            return False

        try:
            print(f"📤 Dosya gönderiliyor: {filepath}")

            # Dosya bilgileri
            filename = os.path.basename(filepath)
            file_size = os.path.getsize(filepath)
            file_hash = self.calculate_file_hash(filepath)

            # Dosyayı oku
            with open(filepath, 'rb') as f:
                file_data = f.read()

            # AES ile şifrele
            print("🔐 Dosya şifreleniyor...")
            encrypted_data = self.encrypt_data_aes(file_data)
            if not encrypted_data:
                print("❌ Dosya şifreleme başarısız")
                return False

            fragment_size = 1024  # Her fragment 1 KB
            total_fragments = (len(encrypted_data) + fragment_size - 1) // fragment_size

            # SEND_FILE komutunu gönder
            self.socket.send(b"SEND_FILE")
            time.sleep(0.1)

            # Dosya bilgilerini fragment_size ile gönder
            file_info = f"{filename}|{len(encrypted_data)}|{file_hash}|{fragment_size}"
            self.socket.send(file_info.encode('utf-8'))
            time.sleep(0.1)

            # Fragment gönderimi başlasın!
            sent = 0
            for idx in range(total_fragments):
                frag = encrypted_data[idx * fragment_size: (idx + 1) * fragment_size]
                header = struct.pack("!II", idx, len(frag))
                self.socket.sendall(header + frag)
                sent += 1
                print(f"\r📦 Fragment {idx+1}/{total_fragments} gönderildi.", end='')
            print()

            # Yanıt bekle
            response = self.socket.recv(1024)
            if response == b"FILE_RECEIVED_SUCCESS":
                print("✅ Dosya başarıyla gönderildi!")
                self.stats['files_sent'] += 1
                self.stats['bytes_sent'] += file_size
                return True
            else:
                error_msg = response.decode('utf-8') if response else 'Bilinmeyen hata'
               # print(f"❌ Dosya gönderme başarısız: {error_msg}")
                return False

        except Exception as e:
            print(f"❌ Dosya gönderme hatası: {e}")
            return False

    def send_file_scapy(self, filepath):
        """
        Dosyayı fragmentlere böl, custom IP header ile Scapy üzerinden gönder (DEMO!)
        """
        if not os.path.exists(filepath):
            print(f"❌ Dosya bulunamadı: {filepath}")
            return False

        print(f"📤 (Scapy) IP ile dosya gönderiliyor: {filepath}")
        dest_ip = self.server_host
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)

        # Dosyayı oku
        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Dosyayı AES ile şifrele (mevcut fonksiyonunu kullan!)
        encrypted_data = self.encrypt_data_aes(file_data)
        if not encrypted_data:
            print("❌ Dosya şifreleme başarısız")
            return False

        # Fragmentation (her fragment 1024 byte)
        fragment_size = 1024
        fragments = [encrypted_data[i:i+fragment_size] for i in range(0, len(encrypted_data), fragment_size)]
        total_fragments = len(fragments)
        print(f"🧩 {total_fragments} fragment oluşturuldu.")

        for idx, frag in enumerate(fragments):
            # Fragment index ve toplam fragment bilgisini ekle
            frag_header = struct.pack("!I I", idx, total_fragments)
            payload = frag_header + frag

            # Scapy ile custom IP+UDP paketi gönder (UDP kullan, demo için daha risksiz)
            pkt = IP(dst=dest_ip) / UDP(dport=8888, sport=RandShort()) / Raw(payload)
            send(pkt, verbose=0)
            print(f"📦 Fragment {idx+1}/{total_fragments} gönderildi.")

        print("✅ (Scapy) Dosya fragment olarak gönderildi.")
        return True

    def list_server_files(self):
        """
        Sunucudaki dosyaları listele
        """
        if not self.connected:
            print("❌ Sunucuya bağlı değil")
            return
        
        try:
            self.socket.send(b"LIST_FILES")
            response = self.socket.recv(4096).decode('utf-8')
            
            if response and response != "FILE_LIST_ERROR":
                print("\n📋 Sunucudaki Dosyalar:")
                print("-" * 50)
                
                for line in response.split('\n'):
                    if '|' in line:
                        filename, file_size = line.split('|')
                        file_size_kb = int(file_size) / 1024
                        print(f"📄 {filename} ({file_size_kb:.1f} KB)")
                
                print("-" * 50)
            else:
                print("❌ Dosya listesi alınamadı")
                
        except Exception as e:
            print(f"❌ Dosya listesi hatası: {e}")

    def show_performance_stats(self):
        """
        Performans istatistiklerini göster
        """
        print(f"\n📊 PERFORMANS İSTATİSTİKLERİ")
        print(f"🔗 Bağlantı süresi: {self.stats['connection_time']:.2f} saniye")
        print(f"📤 Gönderilen dosya: {self.stats['files_sent']}")
        print(f"📊 Toplam byte: {self.stats['bytes_sent']}")
        
        if self.stats['transfer_speeds']:
            avg_speed = sum(self.stats['transfer_speeds']) / len(self.stats['transfer_speeds'])
            max_speed = max(self.stats['transfer_speeds'])
            min_speed = min(self.stats['transfer_speeds'])
            
            print(f"🚀 Ortalama hız: {avg_speed:.2f} bytes/s ({avg_speed/1024:.2f} KB/s)")
            print(f"⚡ Maksimum hız: {max_speed:.2f} bytes/s ({max_speed/1024:.2f} KB/s)")
            print(f"🐌 Minimum hız: {min_speed:.2f} bytes/s ({min_speed/1024:.2f} KB/s)")

    def network_analysis(self):
        """
        Ağ analizi gerçekleştir
        """
        print(f"\n🔍 AĞ ANALİZİ")
        print(f"🎯 Hedef: {self.server_host}:{self.server_port}")
        
        # RTT ölçümü
        rtt = self.calculate_rtt(self.server_host)
        
        # Bant genişliği tahmini (basit)
        if self.stats['transfer_speeds']:
            estimated_bandwidth = max(self.stats['transfer_speeds']) * 8  # bits per second
            print(f"📡 Tahmini bant genişliği: {estimated_bandwidth:.0f} bps ({estimated_bandwidth/1024:.1f} Kbps)")

    def disconnect(self):
        """
        Sunucudan bağlantıyı kes
        """
        if self.connected and self.socket:
            try:
                self.socket.send(b"DISCONNECT")
                time.sleep(0.1)
                self.socket.close()
                print("🔌 Sunucudan bağlantı kesildi")
            except:
                pass
            finally:
                self.connected = False
                self.socket = None

    def interactive_menu(self):
        """
        Etkileşimli kullanıcı menüsü
        """
        while True:
            print(f"\n=== SECURE FILE TRANSFER CLIENT ===")
            print(f"🔗 Durum: {'Bağlı' if self.connected else 'Bağlı Değil'}")
            print(f"🎯 Sunucu: {self.server_host}:{self.server_port}")
            
            print("\nSeçenekler:")
            if not self.connected:
                print("1. Sunucuya bağlan")
            else:
                print("2. Dosya gönder")
                print("3. Sunucu dosyalarını listele")
                print("4. Performans istatistikleri")
                print("5. Ağ analizi")
                print("6. Bağlantıyı kes")
                print("7. Low-Level özel paket gönder (header ve checksum demo)")
            print("0. Çıkış")
            
            choice = input("\nSeçiminizi yapın: ").strip()
            
            if choice == '1' and not self.connected:
                self.connect_to_server()
            elif choice == '2' and self.connected:
                filepath = input("Göndermek istediğiniz dosyanın yolunu girin: ").strip()
                if filepath:
                    self.send_file(filepath)
            elif choice == '3' and self.connected:
                self.list_server_files()
            elif choice == '4' and self.connected:
                self.show_performance_stats()
            elif choice == '5' and self.connected:
                self.network_analysis()
            elif choice == '6' and self.connected:
                self.disconnect()  
            elif choice == '7' and self.connected:
                filepath = input("Göndermek istediğiniz dosyanın yolunu girin: ").strip()
                if filepath:
                    self.send_custom_lowlevel_packet(filepath)

            elif choice == '0':
                if self.connected:
                    self.disconnect()
                print("👋 Çıkış yapılıyor...")
                break
            else:
                print("❌ Geçersiz seçim")

def main():
    """
    Ana fonksiyon
    """
    print("=== ADVANCED SECURE FILE TRANSFER CLIENT ===")
    print("Bilgisayar Ağları Dönem Projesi\n")
    
    # Konfigürasyon
    server_host = input("Sunucu adresi (varsayılan: localhost): ").strip() or 'localhost'
    server_port_str = input("Sunucu portu (varsayılan: 8080): ").strip() or '8080'
    password = input("Sunucu parolası (varsayılan: secure123): ").strip() or 'secure123'
    
    try:
        server_port = int(server_port_str)
    except ValueError:
        print("❌ Geçersiz port numarası, varsayılan port kullanılıyor (8080)")
        server_port = 8080
    
    # Client oluştur
    client = SecureFileTransferClient(server_host, server_port, password)
    
    try:
        # Etkileşimli menüyü başlat
        client.interactive_menu()
    except KeyboardInterrupt:
        print("\n🛑 Program durduruldu")
        if client.connected:
            client.disconnect()
    except Exception as e:
        print(f"❌ Client hatası: {e}")

if __name__ == "__main__":
    main()