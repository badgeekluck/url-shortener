package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/consul/api"
	"github.com/lib/pq"
	"github.com/skip2/go-qrcode"
	"github.com/streadway/amqp"
	"golang.org/x/crypto/bcrypt"
)

var (
	redisClient     *redis.Client
	rabbitMqChannel *amqp.Channel
	database        *sql.DB
	consulClient    *api.Client
	ctx             = context.Background()
)

// --- Struct Tanımlamaları ---

type CreateShortURLRequest struct {
	URL         string   `json:"url" binding:"required,url"`
	CustomShort string   `json:"custom_short,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type ClickEvent struct {
	ShortCode string `json:"short_code"`
}

// --- Yardımcı Fonksiyonlar ---

func getConfig(kv *api.KV, key string, defaultValue string) string {
	pair, _, err := kv.Get(key, nil)
	if err != nil || pair == nil {
		log.Printf("Consul'dan '%s' anahtarı okunamadı, varsayılan değer kullanılıyor.", key)
		return defaultValue
	}
	return string(pair.Value)
}

func init() {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = "consul:8500"

	var err error
	consulClient, err = api.NewClient(consulConfig) // <-- BURAYI DEĞİŞTİR (:= yerine = kullandık)

	if err != nil {
		log.Fatalf("Consul istemcisi oluşturulamadı: %v", err)
	}
	kv := consulClient.KV()

	// Ayarları Consul'dan Çek
	redisHost := getConfig(kv, "config/redis/host", "redis")
	redisPort := getConfig(kv, "config/redis/port", "6379")
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	rmqHost := getConfig(kv, "config/rabbitmq/host", "rabbitmq")
	rmqPort := getConfig(kv, "config/rabbitmq/port", "5672")
	rmqAddr := fmt.Sprintf("amqp://guest:guest@%s:%s/", rmqHost, rmqPort)

	dbHost := "postgres"
	dbPort := "5432"
	dbUser := getConfig(kv, "config/postgres/user", "postgres")
	dbPassword := getConfig(kv, "config/postgres/password", "")
	dbName := getConfig(kv, "config/postgres/dbname", "analytics_db")
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		dbUser, dbPassword, dbName, dbHost, dbPort)

	// Servislere Bağlan
	redisClient = redis.NewClient(&redis.Options{Addr: redisAddr})
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Redis sunucusuna bağlanılamadı: %v", err)
	}
	fmt.Println("Shortener-Service: Redis'e başarıyla bağlanıldı.")

	conn, err := amqp.Dial(rmqAddr)
	if err != nil {
		log.Fatalf("RabbitMQ'ya bağlanamadı: %s", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("RabbitMQ kanalı açılamadı: %s", err)
	}
	rabbitMqChannel = ch
	_, err = rabbitMqChannel.QueueDeclare("clicks", true, false, false, false, nil)
	if err != nil {
		log.Fatalf("RabbitMQ kuyruğu oluşturulamadı: %s", err)
	}
	fmt.Println("Shortener-Service: RabbitMQ'ya başarıyla bağlanıldı.")

	database, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("PostgreSQL'e bağlanılamadı: %s", err)
	}
	err = database.Ping()
	if err != nil {
		log.Fatalf("PostgreSQL'e ping atılamadı: %s", err)
	}
	fmt.Println("Shortener-Service: PostgreSQL'e başarıyla bağlanıldı.")

	// Servisi Consul'a Kaydet
	registration := &api.AgentServiceRegistration{
		ID:      "shortener-service-1",
		Name:    "shortener-service",
		Port:    8080,
		Address: "shortener-service",
	}
	err = consulClient.Agent().ServiceRegister(registration)
	if err != nil {
		log.Fatalf("Servis Consul'a kaydedilemedi: %v", err)
	}
	log.Println("Servis başarıyla Consul'a kaydedildi.")
}

func generateShortCode() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 6)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header'ı eksik."})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header formatı hatalı."})
			return
		}
		jwtSecretKey := getConfig(consulClient.KV(), "config/jwt/secret", "default_secret")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("beklenmedik imzalama metodu: %v", token.Header["alg"])
			}
			return []byte(jwtSecretKey), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz veya süresi dolmuş token."})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			userID := claims["sub"].(string)
			c.Set("userID", userID)
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token parse edilemedi."})
			return
		}

		c.Next()
	}
}

func main() {
	router := gin.Default()

	// --- 1. Herkese Açık ve Statik Endpoint'ler ---
	router.POST("/register", func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Parola hash'lenemedi."})
			return
		}
		var newUserID int
		err = database.QueryRow(
			"INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
			req.Email, string(hashedPassword),
		).Scan(&newUserID)
		if err != nil {
			if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
				c.JSON(http.StatusConflict, gin.H{"error": "Bu email adresi zaten kullanımda."})
				return
			}
			log.Printf("Kullanıcı oluşturulurken veritabanı hatası: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı oluşturulamadı."})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"message": "Kullanıcı başarıyla oluşturuldu.", "user_id": newUserID})
	})

	router.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var userID int
		var hashedPassword string
		err := database.QueryRow("SELECT id, password_hash FROM users WHERE email = $1", req.Email).Scan(&userID, &hashedPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz email veya parola."})
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz email veya parola."})
			return
		}
		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Issuer:    "shortener-service",
			Subject:   fmt.Sprintf("%d", userID),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})

		jwtSecretKey := getConfig(consulClient.KV(), "config/jwt/secret", "default_secret")
		tokenString, err := claims.SignedString([]byte(jwtSecretKey))
		if err != nil {
			log.Printf("JWT imzalanamadı: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Giriş yapılamadı."})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	router.POST("/shorten", func(c *gin.Context) {
		var req CreateShortURLRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Unique bir shortCode bulma mantığı aynı kalıyor
		var shortCode string
		if req.CustomShort != "" {
			shortCode = req.CustomShort
			val, err := redisClient.Exists(ctx, shortCode).Result()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası"})
				return
			}
			if val == 1 {
				// Not: Bu kontrol hem Redis'i hem de DB'yi kontrol etmeli.
				c.JSON(http.StatusConflict, gin.H{"error": "Bu özel link daha önce alınmış."})
				return
			}
		} else {
			for {
				shortCode = generateShortCode()
				val, err := redisClient.Exists(ctx, shortCode).Result()
				if err != nil {
					log.Printf("Redis kontrolü sırasında hata: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası"})
					return
				}
				if val == 0 {
					break
				}
			}
		}

		// Önce ana veritabanına (PostgreSQL) yaz. owner_id için sql.NullInt64 kullanarak NULL değer gönder.
		_, err := database.Exec(
			"INSERT INTO links (owner_id, short_code, original_url) VALUES ($1, $2, $3)",
			sql.NullInt64{}, shortCode, req.URL,
		)
		if err != nil {
			// Eğer short_code zaten alınmışsa (UNIQUE constraint), conflict hatası ver.
			if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
				c.JSON(http.StatusConflict, gin.H{"error": "Bu özel link daha önce alınmış."})
				return
			}
			log.Printf("Anonim link oluşturulurken veritabanı hatası: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "URL kaydedilemedi."})
			return
		}

		// PostgreSQL'e başarıyla yazıldıktan sonra, hızlı erişim için Redis'e (cache'e) ekle.
		err = redisClient.Set(ctx, shortCode, req.URL, 0).Err()
		if err != nil {
			log.Printf("KRİTİK HATA: Link DB'ye yazıldı ama Redis'e yazılamadı (anonim). shortCode: %s", shortCode)
			// Bu durumda bile kullanıcıya başarılı cevabı dönebiliriz, çünkü link artık kalıcı.
		}

		c.JSON(http.StatusOK, gin.H{
			"original_url": req.URL,
			"short_url":    "http://localhost:8080/" + shortCode,
		})
	})

	router.GET("/qr/:shortCode", func(c *gin.Context) {
		shortCode := c.Param("shortCode")
		val, err := redisClient.Exists(ctx, shortCode).Result()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası"})
			return
		}
		if val == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Bu kısa link mevcut değil."})
			return
		}
		fullShortURL := "http://localhost:8080/" + shortCode
		pngBytes, err := qrcode.Encode(fullShortURL, qrcode.Medium, 256)
		if err != nil {
			log.Printf("QR kod üretilemedi: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "QR kod oluşturulamadı."})
			return
		}
		c.Header("Content-Type", "image/png")
		c.Data(http.StatusOK, "image/png", pngBytes)
	})

	// --- 2. Korumalı Grup ve Endpoint'ler ---
	authorized := router.Group("/")

	authorized.Use(authMiddleware())
	{
		authorized.POST("/links", func(c *gin.Context) {
			userIDstr, exists := c.Get("userID")
			if !exists {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı ID'si context'te bulunamadı."})
				return
			}
			userID, err := strconv.Atoi(userIDstr.(string))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı ID'si formatı hatalı."})
				return
			}
			var req CreateShortURLRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			var shortCode string
			if req.CustomShort != "" {
				shortCode = req.CustomShort
				val, err := redisClient.Exists(ctx, shortCode).Result()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası"})
					return
				}
				if val == 1 {
					c.JSON(http.StatusConflict, gin.H{"error": "Bu özel link daha önce alınmış."})
					return
				}
			} else {
				for {
					shortCode = generateShortCode()
					val, err := redisClient.Exists(ctx, shortCode).Result()
					if err != nil {
						log.Printf("Redis kontrolü sırasında hata: %v", err)
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası"})
						return
					}
					if val == 0 {
						break
					}
				}
			}

			tx, err := database.Begin()
			if err != nil {
				log.Printf("Transaction başlatılamadı: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "İşlem başlatılamadı."})
				return
			}
			var linkID int
			err = tx.QueryRow(
				"INSERT INTO links (owner_id, short_code, original_url) VALUES ($1, $2, $3) RETURNING id",
				userID, shortCode, req.URL,
			).Scan(&linkID)
			if err != nil {
				tx.Rollback()
				log.Printf("Link oluşturulurken veritabanı hatası: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "URL kaydedilemedi (PostgreSQL)."})
				return
			}
			if len(req.Tags) > 0 {
				for _, tagName := range req.Tags {
					var tagID int
					err = tx.QueryRow(
						"INSERT INTO tags (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
						tagName,
					).Scan(&tagID)
					if err != nil {
						tx.Rollback()
						log.Printf("Etiket oluşturulurken/alınırken veritabanı hatası: %v", err)
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Etiketler işlenemedi."})
						return
					}
					_, err = tx.Exec("INSERT INTO link_tags (link_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", linkID, tagID)
					if err != nil {
						tx.Rollback()
						log.Printf("Link-etiket eşleşmesi oluşturulurken veritabanı hatası: %v", err)
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Etiketler linke bağlanamadı."})
						return
					}
				}
			}
			if err := tx.Commit(); err != nil {
				log.Printf("Transaction commit edilemedi: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "İşlem onaylanamadı."})
				return
			}
			err = redisClient.Set(ctx, shortCode, req.URL, 0).Err()
			if err != nil {
				log.Printf("KRİTİK HATA: Link DB'ye yazıldı ama Redis'e yazılamadı. shortCode: %s", shortCode)
			}
			c.JSON(http.StatusCreated, gin.H{
				"original_url": req.URL,
				"short_url":    "http://localhost:8080/" + shortCode,
			})
		})

		authorized.GET("/links", func(c *gin.Context) {
			userID, _ := c.Get("userID")
			query := `
				SELECT 
					l.short_code, 
					l.original_url, 
					l.created_at, 
					COALESCE(ARRAY_AGG(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') as tags
				FROM 
					links l
				LEFT JOIN 
					link_tags lt ON l.id = lt.link_id
				LEFT JOIN 
					tags t ON lt.tag_id = t.id
				WHERE 
					l.owner_id = $1
				GROUP BY 
					l.id
				ORDER BY 
					l.created_at DESC`
			rows, err := database.Query(query, userID)
			if err != nil {
				log.Printf("Linkler çekilirken veritabanı hatası: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Linkler alınamadı."})
				return
			}
			defer rows.Close()

			type LinkInfo struct {
				ShortCode   string    `json:"short_code"`
				OriginalURL string    `json:"original_url"`
				CreatedAt   time.Time `json:"created_at"`
				Tags        []string  `json:"tags"`
			}
			var links []LinkInfo
			for rows.Next() {
				var link LinkInfo
				if err := rows.Scan(&link.ShortCode, &link.OriginalURL, &link.CreatedAt, pq.Array(&link.Tags)); err != nil {
					log.Printf("Satır okunamadı: %s", err)
					continue
				}
				links = append(links, link)
			}
			c.JSON(http.StatusOK, links)
		})
	}

	// --- 3. Herkese Açık ve Dinamik Endpoint (EN SONDA) ---
	router.GET("/:shortCode", func(c *gin.Context) {
		shortCode := c.Param("shortCode")
		originalURL, err := redisClient.Get(ctx, shortCode).Result()
		if err == redis.Nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Kısa URL bulunamadı."})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası."})
			return
		}
		event := ClickEvent{ShortCode: shortCode}
		eventBody, _ := json.Marshal(event)
		err = rabbitMqChannel.Publish(
			"", "clicks", false, false,
			amqp.Publishing{ContentType: "application/json", Body: eventBody},
		)
		if err != nil {
			log.Printf("RabbitMQ'ya mesaj gönderilemedi: %s", err)
		}
		c.Redirect(http.StatusFound, originalURL)
	})

	router.Run(":8080")
}
