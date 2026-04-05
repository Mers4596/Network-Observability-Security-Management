<div align="center">

# 🛡️ Network Observability & Security Management
### *Nebula Net — Gerçek Zamanlı Ağ İzleme ve Güvenlik Yönetim Platformu*

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![SocketIO](https://img.shields.io/badge/Socket.IO-Real--Time-010101?style=for-the-badge&logo=socket.io&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

---

## 📌 Proje Hakkında

**Network Observability & Security Management** (kod adı: *Nebula Net*), kurumsal ağlardaki tüm cihazları, trafik akışlarını ve güvenlik olaylarını **gerçek zamanlı** olarak izlemek, analiz etmek ve yönetmek amacıyla geliştirilmiş bütünleşik bir web tabanlı platformdur.

Proje; **gözlemlenebilirlik (observability)** ilkelerini temel alarak ağ altyapısındaki görünürlüğü maksimize etmek, anormal davranışları erken tespit etmek ve güvenlik ekiplerine eyleme geçirilebilir içgörüler sunmak için tasarlanmıştır.

> **Hedef Kitle:** SOC analistleri, ağ mühendisleri, sistem yöneticileri ve BT güvenlik ekipleri.

---

## 🎯 Temel Amaç ve Motivasyon

Modern kurumsal ağlar; sunucular, iş istasyonları, IoT cihazları ve ağ donanımlarından oluşan karmaşık bir ekosistemdir. Bu karmaşıklık, güvenlik açıklarını ve operasyonel kör noktaları beraberinde getirir. Bu proje şu soruları yanıtlamak için doğmuştur:

- 🔍 **"Ağımda tam olarak ne var?"** → Varlık yönetimi ve topoloji haritalama  
- ⚡ **"Şu an ne oluyor?"** → Canlı trafik akışı ve anomali tespiti  
- 🚨 **"Tehdit var mı, nerede?"** → Otomatik güvenlik taraması ve uyarı motoru  
- 🔐 **"Kim, neye erişebilir?"** → Erişim kontrolü ve güvenlik duvarı kural yönetimi  
- 📋 **"Geçmişte ne oldu?"** → Denetim izi ve olay günlükleri  

---

## 🏗️ Mimari Genel Bakış

```
┌─────────────────────────────────────────────────────────────┐
│                    NEBULA NET PLATFORM                       │
├─────────────┬───────────────────────────────┬───────────────┤
│  FRONTEND   │        BACKEND (Flask)         │   VERİTABANI  │
│  (Jinja2 +  │                               │   (SQLite WAL)│
│  Vanilla JS)│  ┌──────────────────────────┐ │               │
│             │  │  REST API Katmanı        │ │  ┌──────────┐ │
│  9 Sayfa    │  │  /api/devices            │ │  │ devices  │ │
│  Dashboard  │  │  /api/traffic            │ │  │ traffic  │ │
│  Topology   │  │  /api/alerts             │ │  │ alerts   │ │
│  Assets     │  │  /api/security-scans     │ │  │ users    │ │
│  Traffic    │  │  /api/access-rules       │ │  │ rules    │ │
│  Security   │  │  /api/settings           │ │  │ scans    │ │
│  Access     │  └──────────────────────────┘ │  └──────────┘ │
│  Alerts     │  ┌──────────────────────────┐ │               │
│  Settings   │  │  Socket.IO (Gerçek Zaman)│ │               │
│             │  └──────────────────────────┘ │               │
│             │  ┌──────────────────────────┐ │               │
│             │  │  Arka Plan İş Parçacıkları│ │               │
│             │  │  • Trafik Simülatörü     │ │               │
│             │  │  • DB Flusher (Batch)    │ │               │
│             │  │  • Sağlık Özetleyici     │ │               │
│             │  └──────────────────────────┘ │               │
└─────────────┴───────────────────────────────┴───────────────┘
```

---

## ✨ Özellikler

### 📊 Ana Gösterge Paneli (`/dashboard`)
- Anlık ağ sağlığı metrikleri (bant genişliği, aktif cihaz sayısı, ortalama risk skoru)
- Kritik uyarı sayacı ve gerçek zamanlı güncelleme
- Dakika bazlı ağ sağlığı zaman çizelgesi

### 🗺️ Ağ Topolojisi (`/topology`)
- Cihazlar arası fiziksel bağlantı haritası
- Hiyerarşik ağ yapısı görselleştirmesi (router → switch → endpoint)
- Bağlantı durumu (up/down) gösterimi

### 💻 Varlık Yönetimi (`/assets`)
- Tüm ağ cihazlarının envanteri (sunucu, iş istasyonu, IoT, ağ donanımı)
- Risk skoru, işletim sistemi, konum, departman bilgisi
- **Shadow IT** bayrağı — onaysız cihaz tespiti
- Cihaz izolasyonu, manuel tarama ve onay işlemleri
- Cihaz başına güvenlik açığı raporları

### 📡 Trafik Analizi (`/traffic`)
- Gerçek zamanlı TCP/UDP/ICMP trafik akışı izleme
- L7 uygulama protokolü tespiti (HTTPS, SSH, DNS, SMTP, SMB, FTP)
- Bant genişliği, gecikme (latency) ve paket kaybı metrikleri
- **Anomali tespiti**: Eşik tabanlı otomatik işaretleme

### 🔒 Güvenlik Denetimi (`/securityAudit`)
- Otomatik ve manuel güvenlik taramaları
- CVE kimlik tespiti ve açık port analizi
- Güvenlik açığı raporları (Critical / High / Medium / Info)
- Tarama geçmişi ve süre takibi

### 🔑 Erişim Kontrolü (`/accessControl`)
- Güvenlik duvarı ve erişim kuralı yönetimi
- Kural öncelik sıralaması (Allow / Block / Monitor)
- Kaynak-hedef korelasyonu ve protokol filtreleme

### 🚨 Uyarı Merkezi (`/alerts`)
- Otomatik oluşturulan güvenlik uyarıları
- Severity sınıflandırması (Critical / Warning / Info)
- Trafik anomalisi bildirimleri
- Çözüm durumu takibi (`resolved_at`)

### ⚙️ Sistem Ayarları (`/settings`)
- Konuk Wi-Fi, otomatik tarama ve güvenlik seviyesi yapılandırması
- Veri saklama politikası (retention days)
- Sistem adı, dil ve saat dilimi ayarları

### 📋 Denetim İzi
- Her yönetici işlemi (izolasyon, tarama, kural değişikliği vb.) otomatik olarak `user_action_logs` tablosuna kaydedilir
- IP adresi, operatör adı, hedef nesne ve ayrıntı bilgisiyle tam iz bırakır

---

## 🛠️ Teknoloji Yığını

| Katman | Teknoloji | Amaç |
|--------|-----------|-------|
| **Backend** | Python 3.11+, Flask 3.x | REST API ve sayfa sunumu |
| **Gerçek Zamanlı** | Flask-SocketIO | Canlı veri akışı |
| **Veritabanı** | SQLite (WAL modu) | Yüksek eşzamanlılıklı veri depolama |
| **Frontend** | Jinja2 Templates, Vanilla JS | Dinamik arayüz |
| **Stil** | Vanilla CSS | Özel tasarım sistemi |
| **İş Parçacıkları** | Python `threading` | Arka plan işlemleri |

---

## 📁 Proje Yapısı

```
Network-Observability-Security-Management/
│
├── app.py                        # Ana Flask uygulaması — tüm API ve arka plan işleri
├── reset_db.py                   # Veritabanını sıfırlama ve yeniden tohumlama betiği
├── system_audit.py               # Sistem denetim yardımcı aracı
├── observability_v2.db           # SQLite veritabanı (otomatik oluşturulur, git'te yok)
│
├── templates/                    # Jinja2 HTML şablonları
│   ├── base.html                 # Ortak düzen (sidebar, navbar, script importları)
│   ├── dashboard.html            # Ana gösterge paneli
│   ├── topology.html             # Ağ topoloji haritası
│   ├── assets.html               # Cihaz envanter yönetimi
│   ├── traffic.html              # Trafik analizi ve akış izleme
│   ├── securityAudit.html        # Güvenlik taraması ve zafiyet raporlama
│   ├── accessControl.html        # Güvenlik duvarı ve erişim kuralları
│   ├── alerts.html               # Güvenlik uyarı merkezi
│   └── settings.html             # Sistem yapılandırma ayarları
│
├── static/
│   ├── css/
│   │   ├── main.css              # Global stil sistemi
│   │   └── pages/               # Sayfaya özgü stiller
│   └── js/
│       ├── core.js               # Temel yardımcı fonksiyonlar ve API istemcisi
│       ├── store.js              # Merkezi uygulama durum yöneticisi
│       └── lang-config.js        # Çok dilli destek yapılandırması
│
└── SQL Ve Model Bilgileri/
    └── devicesTable.xlsx         # Cihaz veri modeli referans belgesi
```

---

## 🗄️ Veritabanı Şeması

| Tablo | Açıklama |
|-------|----------|
| `devices` | Tüm ağ cihazları, risk skoru, durum ve hiyerarşi |
| `traffic_logs` | L3/L7 trafik kayıtları, anomali bayrağı, performans metrikleri |
| `security_alerts` | Otomatik oluşan güvenlik uyarıları |
| `security_scans` | Tarama sonuçları, CVE kimlik listesi, süre |
| `vulnerability_reports` | Zafiyet bulguları ve açıklama |
| `access_rules` | Güvenlik duvarı ve erişim kontrol politikaları |
| `users` | Kullanıcı hesapları ve roller |
| `user_action_logs` | Yönetici işlem denetim izi |
| `system_settings` | Platform yapılandırma parametreleri |
| `network_health_history` | Dakika bazlı ağ sağlığı zaman çizelgesi |
| `topology_links` | Cihazlar arası fiziksel/mantıksal bağlantı haritası |
| `safe_zones` | Güvenli IP aralığı tanımlamaları |

---

## 🚀 Kurulum ve Çalıştırma

### Ön Gereksinimler
- Python 3.11+
- pip

### 1. Depoyu Klonla
```bash
git clone https://github.com/Mers4596/Network-Observability-Security-Management.git
cd Network-Observability-Security-Management
```

### 2. Sanal Ortam Oluştur ve Aktifleştir
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Bağımlılıkları Yükle
```bash
pip install flask flask-socketio
```

### 4. Uygulamayı Başlat
```bash
python app.py
```

Uygulama `http://127.0.0.1:5000` adresinde çalışmaya başlar.  
Veritabanı (`observability_v2.db`) ilk çalıştırmada otomatik olarak oluşturulur ve örnek verilerle doldurulur.

### 5. Veritabanını Sıfırla (İsteğe Bağlı)
```bash
python reset_db.py
```

---

## ⚙️ Arka Plan İş Parçacıkları

Uygulama başlatıldığında 3 daemon thread otomatik olarak devreye girer:

| Thread | İşlev |
|--------|--------|
| `Traffic-Sim` | Her saniye rastgele trafik verisi üretir; anomali bayrağı ve risk skoru atar |
| `DB-Flusher` | Trafik tamponunu batch-insert ile 2 saniyede bir veritabanına aktarır |
| `Health-Summarizer` | Her dakika ağ genelindeki bant genişliği, risk ve uyarı özetini kaydeder |

---

## 🔌 API Referansı (Özet)

| Endpoint | Method | Açıklama |
|----------|--------|----------|
| `/api/devices` | GET | Tüm cihazları listele |
| `/api/devices/scan/<id>` | POST | Manuel güvenlik taraması başlat |
| `/api/devices/isolate/<id>` | POST | Cihazı ağdan izole et |
| `/api/devices/restore/<id>` | POST | Cihazı ağa geri al |
| `/api/devices/approve/<id>` | POST | Yeni cihazı onayla |
| `/api/traffic` | GET | Trafik kayıtlarını getir |
| `/api/alerts` | GET | Güvenlik uyarılarını listele |
| `/api/alerts/<id>/resolve` | POST | Uyarıyı çözümlendi olarak işaretle |
| `/api/security-scans` | GET | Tarama geçmişini getir |
| `/api/access-rules` | GET/POST | Kural listele / yeni kural ekle |
| `/api/access-rules/<id>` | PATCH/DELETE | Kural güncelle / sil |
| `/api/settings` | GET/POST | Sistem ayarlarını oku / güncelle |
| `/api/audit-log` | GET | Denetim izini listele |
| `/api/network-health/history` | GET | Ağ sağlığı zaman çizelgesi |

---

## 🛡️ Güvenlik Notları

- Proje şu an **eğitim ve demonstrasyon** amacıyla geliştirilmektedir.
- Üretim ortamında kullanılmadan önce:
  - `.env` tabanlı gizli yönetimi entegre edilmeli
  - Kullanıcı kimlik doğrulaması (JWT / OAuth2) eklenmeli
  - HTTPS zorunlu hale getirilmeli
  - Mock veri üreticisi gerçek ağ adaptörleriyle (Scapy / libpcap) değiştirilmeli

---

## 👤 Geliştirici

**Mehmet Ersolak**  
📧 mehmet@nebulanets.local  
🔗 [GitHub](https://github.com/Mers4596)

---

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) kapsamında lisanslanmıştır.

---

<div align="center">
  <sub>Built with ❤️ using Python, Flask & SQLite</sub>
</div>