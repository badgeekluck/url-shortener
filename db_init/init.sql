-- Bu dosya, veritabanı ilk kez oluşturulduğunda tabloları otomatik olarak kurar.

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
                       owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                       short_code VARCHAR(50) UNIQUE NOT NULL,
                       original_url TEXT NOT NULL,
                       created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tıklama olaylarını tutmak için
CREATE TABLE clicks (
                        id SERIAL PRIMARY KEY,
                        short_code VARCHAR(50) NOT NULL,
                        message_id VARCHAR(36) UNIQUE, -- Mükerrer kayıt engelleme için
                        clicked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Benzersiz etiketleri saklamak için
CREATE TABLE tags (
                      id SERIAL PRIMARY KEY,
                      name VARCHAR(50) UNIQUE NOT NULL
);

-- Linkler ve etiketler arasındaki ilişkiyi kuran köprü tablo
CREATE TABLE link_tags (
                           link_id INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
                           tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
                           PRIMARY KEY (link_id, tag_id)
);