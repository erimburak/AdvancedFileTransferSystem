# Advanced Secure File Transfer System

Bu proje, Python kullanılarak geliştirilen **güvenli dosya transferi** uygulamasıdır. `server.py` ve `client.py` dosyaları sayesinde istemci–sunucu arasında şifreli dosya aktarımı gerçekleştirilir. Sistem, dosya bütünlüğünü kontrol etmenin yanı sıra ağ üzerinde düşük seviyeli paket işlemlerine de izin verir.

## Özellikler

- **RSA + AES** kombinasyonu ile şifreleme
- Manuel TCP/UDP paket oluşturma ve parçalama desteği (Scapy kullanır)
- Dosya bütünlüğünü `SHA-256` ile doğrulama
- Basit performans ve ağ analizi araçları
- Kullanımı kolay etkileşimli istemci menüsü

## Kurulum

1. Python 3.8 veya üzeri bir sürüm gereklidir.
2. Gerekli paketleri yüklemek için:
   ```bash
   pip install scapy pycryptodome
   ```
3. RSA anahtarları ve örnek sunucu yapılandırmasını oluşturmak için:
   ```bash
   python generate_rsa_keys.py
   ```
   Bu komut `private_key.pem`, `public_key.pem` ve `server_config.json` dosyalarını üretir.

## Sunucuyu Çalıştırma

```bash
python server.py
```

Varsayılan ayarlar `server_config.json` içinden okunur. Sunucu başladığında `uploads/` klasörüne alınan dosyaları kaydeder.

## İstemciyi Çalıştırma

```bash
python client.py
```

İstemci açıldığında sunucu adresi, port ve parola bilgilerini ister. Bağlandıktan sonra menü üzerinden dosya gönderme, sunucudaki dosyaları listeleme ve ağ analizi yapma gibi seçenekler bulunur.

## Dizin Yapısı

```
advancedFileTransfer/
├── client.py            # İstemci uygulaması
├── server.py            # Sunucu uygulaması
├── generate_rsa_keys.py # Anahtar üretme ve konfigürasyon aracı
├── server_config.json   # Varsayılan sunucu ayarları
├── public_key.pem       # Örnek public key (geliştirme için)
├── private_key.pem      # Örnek private key (geliştirme için)
```

> **Not:** Depodaki anahtar dosyaları yalnızca geliştirme amacıyla sağlanmıştır. Üretim ortamında kendi anahtar çiftinizi oluşturmanız önerilir.

## Katkı

Pull request'ler memnuniyetle karşılanır. Hata bildirimleri veya geliştirme önerilerinizi Issues bölümünden iletebilirsiniz.

