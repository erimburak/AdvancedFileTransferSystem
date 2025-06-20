# Advanced Secure File Transfer System

Bu depo, dosya aktarımında yüksek güvenlik ve esneklik sağlamayı hedefleyen bir "Gelişmiş Güvenli Dosya Transferi" projesini içerir. Python ile yazılan sunucu ve istemci bileşenleri, dosya transferinde şifreleme, bütünlük doğrulama, manuel paketleme gibi ağ katmanı seviyesinde işlemler yapabilmektedir.

## Genel Bakış

Projede iki ana bileşen vardır:

1. **Sunucu (server.py)** – Dosya alımını, kimlik doğrulamasını ve bütünlük kontrollerini gerçekleştirir. RSA/AES tabanlı oturum anahtarı yönetimi ile gelen dosyaları `uploads/` dizinine kaydeder.
2. **İstemci (client.py)** – Sunucuya bağlanır, dosyayı şifreler, parçalara böler ve transfer eder. Ayrıca RTT ölçümü, bant genişliği tahmini gibi küçük ağ analizi araçları içerir.

Sistem, klasik TCP dosya aktarımı dışında Scapy kullanarak low-level paket oluşturma, IP/UDP fragmentasyonu ve özel checksum hesaplama gibi gelişmiş özellikler sunar. Böylece hem güvenli hem de ağ seviyesinde incelenebilir bir aktarım mekanizması elde edilir.

## Temel Özellikler

- **Çift Katmanlı Şifreleme:** İletişim başlangıcında RSA ile güvenli bir şekilde AES anahtarı paylaşıldıktan sonra tüm dosya verisi AES-256-CBC ile şifrelenir.
- **Manuel Paketleme:** Gerek duyulduğunda paket başlıkları (TTL, flag, offset) elle ayarlanabilir. Bu sayede düşük seviyeli protokol deneyleri yapılabilir.
- **Bütünlük Doğrulama:** Gönderilen her dosyanın SHA-256 hash değeri karşılaştırılır. Hata durumunda transfer geçersiz sayılır.
- **Performans Metrikleri:** Aktarım süresi, bağlantı zamanı ve tahmini bant genişliği hesapları tutulur. Hem istemci hem de sunucu tarafında kullanılabilir.
- **Etkileşimli Menü:** İstemci tarafında menü tabanlı kullanım mevcuttur. Dosya gönderme, sunucu dosyalarını listeleme ve ağ analizi tek komutla yapılır.

## Kurulum

1. **Python 3.8+** sürümünün kurulu olduğundan emin olun.
2. Proje dizinine girerek gerekli paketleri yükleyin:

   ```bash
   pip install scapy pycryptodome
   ```
3. RSA anahtarları ve örnek konfigürasyonu oluşturmak için:

   ```bash
   python generate_rsa_keys.py
   ```
   Bu işlem `private_key.pem`, `public_key.pem` ve `server_config.json` dosyalarını üretir.
4. Sunucu ve istemci çalışırken aynı dizinde bu anahtarların bulunması gerekir.

## Sunucunun Çalışma Mantığı

Sunucu başlatıldığında `server_config.json` dosyası okunarak ağ ayarları ve güvenlik parametreleri yüklenir. Gelen her yeni bağlantıda şu adımlar gerçekleşir:

1. **TCP Handshake** – İstemci ile basit bir TCP el sıkışması yapılır.
2. **AES Anahtarı Alımı** – İstemci, AES oturum anahtarını RSA ile şifreleyip gönderir. Sunucu bu veriyi çözer ve saklar.
3. **Parola Doğrulama** – İstemci, yine RSA ile şifrelenmiş parolayı yollar. Doğruysa bağlantı onaylanır.
4. **Dosya Transferi** – Dosya bilgileri alınır, fragment sayısı hesaplanır ve tüm parçalar eksiksiz gelene dek beklenir. Parçalar birleşip AES ile çözüldükten sonra bütünlük kontrolü yapılır. Başarılıysa `uploads/` dizinine kaydedilir.
5. **İstatistik Güncelleme** – Bağlantı ve dosya bilgilerinin sayacı tutulur, kapatma sırasında ekrana özet bilgiler basılır.

## İstemcinin Çalışma Mantığı

İstemci programı çalıştırıldığında kullanıcıdan sunucu adresi, portu ve parola bilgileri alınır. Bağlantı kurulduktan sonra:

1. RSA public anahtar okunur ve hafızada tutulur.
2. Rastgele bir AES oturum anahtarı ve IV oluşturulur, RSA ile şifrelenip sunucuya yollanır.
3. Kullanıcının girdiği parola RSA ile şifrelenip sunucuya gönderilir.
4. Sunucu onay verdikten sonra seçilen dosya okunur, AES ile şifrelenir ve parçalara bölünür.
5. Her parça sırayla sunucuya gönderilir. İsteğe bağlı olarak `send_file_scapy` fonksiyonu ile UDP üzerinden özel paketler de kullanılabilir.
6. İşlem sonunda sunucudan alınan yanıt ile aktarımın başarılı olup olmadığı bildirilir.

## RSA ve AES ile Şifreleme Süreci

Transfer süreci hibrit şifreleme tekniğini temel alır:

1. İstemci, sunucunun public anahtarını kullanarak AES anahtarını şifreler.
2. Sunucu kendi private anahtarı ile bu veriyi çözer. Böylece taraflar ortak AES anahtarına sahip olur.
3. Dosya verisi AES-256 ile blok bazlı (CBC) şekilde şifrelenir. Eklenen padding sayesinde dosya boyutu blok uzunluğunun katı haline getirilir.
4. Karşı taraf gelen veriyi aynı IV ile çözer ve bütünlük hash'i kontrol eder.

Bu yöntem hem anahtar alışverişinde güvenlik sağlar hem de büyük dosyaların hızlıca aktarılmasına olanak tanır.

## Paket ve Fragmentasyon İşlemleri

Projede ağ seviyesinde deneysel çalışmalar yapılabilmesi için Scapy kütüphanesi kullanılır. İstemci, `send_custom_lowlevel_packet` fonksiyonu ile IP header alanlarını manuel olarak ayarlayabilir ve paketleri birer birer yollayabilir. Bunun yanında `fragment_data` fonksiyonu dosyayı belirlenen boyutlarda parçalara ayırır. Sunucu tarafında ise bu parçalar sırayla toplanır ve yeniden birleştirilir.

Bu özellikler sayesinde Wireshark gibi araçlarla paketlerin TTL, flag ve offset değerleri izlenebilir; checksum hesaplarının doğruluğu test edilebilir.

## Sunucu Konfigürasyonu (`server_config.json`)

Konfigürasyon dosyası aşağıdaki örnek yapıyı içerir:

```json
{
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
        "max_file_size": 104857600,
        "compression": true
    }
}
```

- **server.host/port** – Sunucunun dinleyeceği adres ve port
- **server.password** – İstemcilerle paylaşılan parolanın hash edilmemiş hali
- **security.rsa_key_size** – Anahtarların bit uzunluğu (varsayılan 2048)
- **performance.chunk_size** – Dosya fragment boyutu (byte)

Gerekirse bu dosyada değişiklik yaparak ağ ayarlarını ve güvenlik parametrelerini özelleştirebilirsiniz.

## Örnek Kullanım Senaryosu

1. Sunucu tarafında `python server.py` komutu ile dinleme başlatılır.
2. Başka bir terminalde `python client.py` çalıştırılır ve sunucu bilgileri girilir.
3. İstemci menüsünden "Dosya gönder" seçeneği ile istenilen dosya seçilir.
4. Aktarım tamamlandığında sunucuda `uploads/` dizini altında dosya görülür.
5. İstemci "Ağ analizi" menüsü ile RTT ölçümü ve tahmini bant genişliği değerlerini görüntüleyebilir.

## Dizin Yapısı ve Dosyalar

```
advancedFileTransfer/
├── client.py             # İstemci uygulaması
├── server.py             # Sunucu uygulaması
├── generate_rsa_keys.py  # RSA anahtar üretimi ve konfigürasyon
├── server_config.json    # Varsayılan sunucu ayarları
├── public_key.pem        # Örnek public key (geliştirme amaçlı)
├── private_key.pem       # Örnek private key (geliştirme amaçlı)
└── uploads/              # Sunucuya gelen dosyaların tutulduğu klasör (oluşturulur)
```

Bu dizin yapısı geliştiricilerin projeyi hızlıca anlamasını sağlar. `uploads/` klasörü ilk çalıştırmada otomatik oluşur.

## Güvenlik Notları

Depodaki RSA anahtarları yalnızca deneme ve geliştirme sürecinde kolaylık sağlaması için eklenmiştir. Üretim ortamında kesinlikle kendi anahtar çiftinizi üretmeniz ve parolanızı daha güvenli yöntemlerle saklamanız gerekmektedir. Ayrıca, Scapy ile gönderilen düşük seviyeli paketler gerçek ağlarda kısıtlamalara takılabilir, bu nedenle testlerinizi izole ortamlarda yapmanız önerilir.

## Katkı

Projeye katkıda bulunmak isterseniz pull request açabilir veya sorun bildirimlerinizi "Issues" bölümünde paylaşabilirsiniz. Her türlü geri bildirim, yeni özellik önerileri ve hata raporları gelişime katkı sağlar.

## Lisans

Bu proje MIT lisansı ile lisanslanmıştır. Ayrıntılar için lütfen `LICENSE` dosyasını inceleyin.

