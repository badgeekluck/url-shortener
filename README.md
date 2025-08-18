# Go ile Mikroservis URL Kısaltma Projesi

Bu proje, Go dili kullanılarak geliştirilmiş, kullanıcı hesapları ve tıklama analitiği gibi özellikler içeren modern bir mikroservis mimarisine sahip URL kısaltma uygulamasıdır. Tüm sistem, Docker ve Docker Compose kullanılarak konteynerize edilmiştir ve tek bir komutla çalıştırılabilir.

## ⭐ Özellikler

- **Kullanıcı Yönetimi:** Güvenli parola hash'leme (`bcrypt`) ile kullanıcı kaydı ve JWT (JSON Web Token) tabanlı giriş sistemi.
- **Link Yönetimi:**
    - Giriş yapmış kullanıcılar için link oluşturma ve listeleme.
    - Hem rastgele hem de kullanıcı tanımlı **özel kısa linkler** oluşturma.
    - Link çakışma kontrolü.
- **Asenkron Analitik:** Tıklama olayları, ana yönlendirme işlemini yavaşlatmamak için RabbitMQ üzerinden asenkron olarak işlenir.
- **Analitik API:** Her bir link için toplam tıklanma sayısı ve son tıklanma zamanları gibi istatistikleri sunan bir API.
- **Konteynerizasyon:** Tüm proje, Docker ve Docker Compose ile paketlenmiştir, bu da geliştirme ve dağıtım süreçlerini basitleştirir.

## 🛠️ Kullanılan Teknolojiler

- **Backend:** Go, Gin Web Framework
- **Veritabanları:**
    - **PostgreSQL:** Kullanıcılar, linkler ve analitik verileri için kalıcı ana veritabanı.
    - **Redis:** Yüksek hızlı yönlendirme ve çakışma kontrolü için önbellek (cache).
- **Mesajlaşma:** RabbitMQ (Servisler arası asenkron iletişim için).
- **Kimlik Doğrulama:** JWT (JSON Web Tokens)
- **Containerization:** Docker, Docker Compose

## 🚀 Başlarken

Projeyi yerel makinenizde çalıştırmak için aşağıdaki adımları izleyin.

### Gereksinimler

- Git
- Docker
- Docker Compose

### Kurulum

1.  **Projeyi klonlayın:**
    ```sh
    git clone <proje-github-linki>
    cd url-shortener
    ```

2.  **Ortam Değişkenlerini Ayarlayın:**
    Projenin ana dizininde `.env` adında bir dosya oluşturun ve içeriğini aşağıdaki gibi doldurun.
    ```ini
    # PostgreSQL Ayarları
    DB_HOST=postgres
    DB_PORT=5432
    DB_USER=
    DB_PASSWORD=
    DB_NAME=

    # Redis Ayarları
    REDIS_HOST=
    REDIS_PORT=

    # RabbitMQ Ayarları
    RABBITMQ_HOST=rabbitmq
    RABBITMQ_PORT=5672

    # JWT Ayarları
    JWT_SECRET_KEY=buraya-cok-guvenli-ve-tahmin-edilemez-bir-metin-yaz
    ```

3.  **Uygulamayı Başlatın:**
    Aşağıdaki komut, tüm servislerin imajlarını oluşturacak ve konteynerleri arka planda başlatacaktır.
    ```sh
    docker-compose up --build -d
    ```

4.  **Veritabanı Tablolarını Oluşturun:**
    Uygulama başladıktan sonra, kullandığınız bir veritabanı istemcisi (DBeaver, DataGrip vb.) ile `localhost:5433` adresindeki PostgreSQL veritabanına bağlanın ve aşağıdaki SQL komutlarını çalıştırarak tabloları oluşturun.

    <details>
    <summary>Tablo Oluşturma SQL Komutları</summary>

    ```sql
    -- Kullanıcıları tutmak için
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Linkleri ve sahiplerini tutmak için
    CREATE TABLE links (
        id SERIAL PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id),
        short_code VARCHAR(50) UNIQUE NOT NULL,
        original_url TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Tıklama olaylarını tutmak için
    CREATE TABLE clicks (
        id SERIAL PRIMARY KEY,
        short_code VARCHAR(10) NOT NULL,
        clicked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
    ```
    </details>

##  API Endpoint'leri

### Herkese Açık Endpoint'ler

| Metot | Path | Açıklama |
| :--- | :--- | :--- |
| `POST` | `/register` | Yeni kullanıcı hesabı oluşturur. |
| `POST` | `/login` | Giriş yapar ve bir JWT döner. |
| `GET` | `/:shortCode` | Kısa linki orijinal adresine yönlendirir. |

### Korumalı Endpoint'ler
*Bu endpoint'leri kullanmak için `Authorization: Bearer <TOKEN>` header'ı gereklidir.*

| Metot | Path | Açıklama |
| :--- | :--- | :--- |
| `POST` | `/links` | Giriş yapmış kullanıcı için yeni bir kısa link oluşturur. |
| `GET` | `/links` | Giriş yapmış kullanıcının tüm linklerini listeler. |
| `GET` | `/analytics/:shortCode` | Belirtilen kısa link için tıklanma istatistiklerini döner. |