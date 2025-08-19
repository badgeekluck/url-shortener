package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
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
	rdb     *redis.Client
	rmqChan *amqp.Channel // RabbitMQ kanalı global
	db      *sql.DB
	ctx     = context.Background()
)

type ClickEvent struct {
	ShortCode string `json:"short_code"`
}

type CreateShortURLRequest struct {
	URL         string `json:"url" binding:"required,url"`
	CustomShort string `json:"custom_short,omitempty"` // omitempty => alan gönderilmezse boş olarak işlenir, hata vermez.
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func getConfig(kv *api.KV, key string, defaultValue string) string {
	pair, _, err := kv.Get(key, nil)
	if err != nil || pair == nil {
		log.Printf("Consul'dan '%s' anahtarı okunamadı, varsayılan değer kullanılıyor.", key)
		return defaultValue
	}
	return string(pair.Value)
}

func init() {

	// --- 1. Consul'a Bağlan ---
	consulConfig := api.DefaultConfig()
	consulConfig.Address = "consul:8500"
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		log.Fatalf("Consul istemcisi oluşturulamadı: %v", err)
	}
	kv := consulClient.KV()

	// Redis Ayarları
	redisHost := getConfig(kv, "config/redis/host", "redis")
	redisPort := getConfig(kv, "config/redis/port", "6379")

	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	// RabbitMQ Ayarları
	rmqHost := getConfig(kv, "config/rabbitmq/host", "rabbitmq")
	rmqPort := getConfig(kv, "config/rabbitmq/port", "5672")

	rmqAddr := fmt.Sprintf("amqp://guest:guest@%s:%s/", rmqHost, rmqPort)

	// PostgreSQL Ayarları
	dbHost := "postgres" // Şimdilik servis keşfi olmadan, Docker DNS kullanıyoruz
	dbPort := "5432"
	dbUser := getConfig(kv, "config/postgres/user", "postgres")
	dbPassword := getConfig(kv, "config/postgres/password", "")
	dbName := getConfig(kv, "config/postgres/dbname", "analytics_db")

	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		dbUser, dbPassword, dbName, dbHost, dbPort)

	// Redis Bağlantısı
	rdb = redis.NewClient(&redis.Options{Addr: redisAddr})
	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Redis sunucusuna bağlanılamadı: %v", err)
	}
	fmt.Println("Shortener-Service: Redis'e başarıyla bağlanıldı.")

	// RabbitMQ Bağlantısı
	conn, err := amqp.Dial(rmqAddr)
	if err != nil {
		log.Fatalf("RabbitMQ'ya bağlanamadı: %s", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("RabbitMQ kanalı açılamadı: %s", err)
	}
	rmqChan = ch
	_, err = rmqChan.QueueDeclare("clicks", true, false, false, false, nil)
	if err != nil {
		log.Fatalf("RabbitMQ kuyruğu oluşturulamadı: %s", err)
	}
	fmt.Println("Shortener-Service: RabbitMQ'ya başarıyla bağlanıldı.")

	// PostgreSQL Bağlantısı
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("PostgreSQL'e bağlanılamadı: %s", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatalf("PostgreSQL'e ping atılamadı: %s", err)
	}
	fmt.Println("Shortener-Service: PostgreSQL'e başarıyla bağlanıldı.")

	// --- 4. Servisi Consul'a Kaydet ---
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
		// 1. Authorization header'ını al
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header'ı eksik."})
			return
		}

		// Header "Bearer <token>" formatında olmalı. Token'ı ayır.
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header formatı hatalı."})
			return
		}

		// 2. Token'ı parse et ve doğrula
		jwtSecret := os.Getenv("JWT_SECRET_KEY")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// İmzalama metodunun beklediğimiz gibi olduğunu kontrol et
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("beklenmedik imzalama metodu: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz veya süresi dolmuş token."})
			return
		}

		// 3. Token geçerliyse, içindeki bilgileri (claims) al
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// user_id'yi (Subject) alıp context'e ekle.
			// Bu sayede ana handler fonksiyonu bu bilgiye erişebilir.
			userID := claims["sub"].(string)
			c.Set("userID", userID)
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token parse edilemedi."})
			return
		}

		// Her şey yolundaysa, bir sonraki fonksiyona (ana handler'a) geç
		c.Next()
	}
}

func main() {
	router := gin.Default()

	// Register
	router.POST("/register", func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Parola hash'lenemedi."})
			return
		}

		// create new user
		var newUserID int
		err = db.QueryRow(
			"INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
			req.Email,
			string(hashedPassword),
		).Scan(&newUserID)

		if err != nil {
			// check pq: unique_violation (23505)
			if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
				c.JSON(http.StatusConflict, gin.H{"error": "Bu email adresi zaten kullanımda."})
				return
			}
			log.Printf("Kullanıcı oluşturulurken veritabanı hatası: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı oluşturulamadı."})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "Kullanıcı başarıyla oluşturuldu.",
			"user_id": newUserID,
		})
	})

	router.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 1. Kullanıcıyı email adresine göre veritabanında bul
		var userID int
		var hashedPassword string
		err := db.QueryRow("SELECT id, password_hash FROM users WHERE email = $1", req.Email).Scan(&userID, &hashedPassword)
		if err != nil {
			// Kullanıcı bulunamazsa veya başka bir DB hatası olursa, yetkisiz hatası dön.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz email veya parola."})
			return
		}

		// 2. Gelen parolayla veritabanındaki hash'i karşılaştır
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
		if err != nil {
			// Parolalar eşleşmiyorsa, yetkisiz hatası dön.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz email veya parola."})
			return
		}

		// 3. Parola doğruysa, JWT oluştur
		// Token'ın içine koyacağımız bilgiler (claims)
		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Issuer:    "shortener-service",
			Subject:   fmt.Sprintf("%d", userID),                          // Token'ın kiminle ilgili olduğu (kullanıcı ID'si)
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // Token 24 saat sonra geçersiz olacak
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})

		// Token'ı gizli anahtarımızla imzala
		jwtSecret := os.Getenv("JWT_SECRET_KEY")
		tokenString, err := claims.SignedString([]byte(jwtSecret))
		if err != nil {
			log.Printf("JWT imzalanamadı: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Giriş yapılamadı."})
			return
		}

		// 4. Token'ı kullanıcıya geri dön
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	router.POST("/shorten", func(c *gin.Context) {
		var req CreateShortURLRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var shortCode string
		if req.CustomShort != "" {
			// Kullanıcı özel bir link istediyse
			shortCode = req.CustomShort

			val, err := rdb.Exists(ctx, shortCode).Result()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası"})
				return
			}
			if val == 1 {
				c.JSON(http.StatusConflict, gin.H{"error": "Bu özel link daha önce alınmış."})
				return
			}
		} else {
			// user özel bir link istemediyse, unique olana kadar random kod
			for {
				shortCode = generateShortCode()
				val, err := rdb.Exists(ctx, shortCode).Result()
				if err != nil {
					log.Printf("Redis kontrolü sırasında hata: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası"})
					return // exit method when get error
				}
				if val == 0 {
					// Eğer val=0 ise, key unique demek
					break
				}
				// val=1 ise döngü devam eder ve yeni bir kod üretir
			}
		}

		// yeni link redise kaydet
		err := rdb.Set(ctx, shortCode, req.URL, 0).Err()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "URL kaydedilemedi."})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"original_url": req.URL,
			"short_url":    "http://localhost:8080/" + shortCode,
		})
	})

	router.GET("/qr/:shortCode", func(c *gin.Context) {
		shortCode := c.Param("shortCode")

		val, err := rdb.Exists(ctx, shortCode).Result()
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

	// Örneğin: /pWk8vN isteği geldiğinde, shortCode = "pWk8vN" olur.
	router.GET("/:shortCode", func(c *gin.Context) {
		shortCode := c.Param("shortCode")
		originalURL, err := rdb.Get(ctx, shortCode).Result()
		if err == redis.Nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Kısa URL bulunamadı."})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Sunucu hatası."})
			return
		}

		// RabbitMQ'ya click olayını gönder
		event := ClickEvent{ShortCode: shortCode}
		eventBody, _ := json.Marshal(event) // Struct'ı JSON'a çevir

		err = rmqChan.Publish(
			"",
			"clicks",
			false, // Mandatory
			false, // Immediate
			amqp.Publishing{
				ContentType: "application/json",
				Body:        eventBody,
			})
		if err != nil {
			log.Printf("RabbitMQ'ya mesaj gönderilemedi: %s", err)
			// Not: Burada hata olsa bile yönlendirmeye devam ediyoruz. Bu, analitik sistemin çökmesinin ana servisi etkilememesini sağlar.
		}
		c.Redirect(http.StatusFound, originalURL)
	})

	// Sadece giriş yapmış kullanıcıların erişebileceği grup
	authorized := router.Group("/")
	authorized.Use(authMiddleware()) // Bu gruba giren her istek önce authMiddleware'den geçecek
	{
		// Giriş yapmış kullanıcının link oluşturması
		authorized.POST("/links", func(c *gin.Context) {
			userIDstr, _ := c.Get("userID")
			userID, _ := strconv.Atoi(userIDstr.(string))

			var req CreateShortURLRequest

			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// Bu bölüm, /shorten endpoint'i ile tamamen aynı.
			var shortCode string
			if req.CustomShort != "" {
				shortCode = req.CustomShort
				val, err := rdb.Exists(ctx, shortCode).Result()
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
					val, err := rdb.Exists(ctx, shortCode).Result()
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

			// 1. Linki hızlı yönlendirme için Redis'e kaydet
			err := rdb.Set(ctx, shortCode, req.URL, 0).Err()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "URL kaydedilemedi (Redis)."})
				return
			}

			// Linki sahibiyle birlikte kalıcı olarak PostgreSQL'e kaydet
			_, err = db.Exec("INSERT INTO links (owner_id, short_code, original_url) VALUES ($1, $2, $3)",
				userID, shortCode, req.URL)

			// Hata durumunda Redis'teki kaydı geri al (ROLLBACK)
			if err != nil {
				log.Printf("Link oluşturulurken veritabanı hatası: %v", err)

				// Telafi işlemi: Redis'e eklenen kaydı sil
				errDel := rdb.Del(ctx, shortCode).Err()
				if errDel != nil {
					log.Printf("KRİTİK HATA: Redis kaydı (%s) geri alınamadı: %v", shortCode, errDel)
				}

				c.JSON(http.StatusInternalServerError, gin.H{"error": "URL kaydedilemedi (PostgreSQL)."})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"original_url": req.URL,
				"short_url":    "http://localhost:8080/" + shortCode,
			})
		})

		// Giriş yapmış kullanıcının kendi linklerini listelemesi
		authorized.GET("/links", func(c *gin.Context) {
			userID, _ := c.Get("userID")

			// Veritabanından bu kullanıcıya ait linkleri çek
			rows, err := db.Query("SELECT short_code, original_url, created_at FROM links WHERE owner_id = $1", userID)
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
			}

			var links []LinkInfo
			for rows.Next() {
				var link LinkInfo
				if err := rows.Scan(&link.ShortCode, &link.OriginalURL, &link.CreatedAt); err != nil {
					log.Printf("Satır okunamadı: %s", err)
					continue
				}
				links = append(links, link)
			}

			c.JSON(http.StatusOK, links)
		})
	}

	router.Run()
}
