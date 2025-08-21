package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/consul/api"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/streadway/amqp"
)

type ClickEvent struct {
	ShortCode string `json:"short_code"`
	MessageID string `json:"-"` // JSON'dan gelmeyecek, AMQP header'ından gelecek.
}

type AnalyticsResult struct {
	TotalClicks  int64       `json:"total_clicks"`
	RecentClicks []time.Time `json:"recent_clicks"`
}

func getConfig(kv *api.KV, key string, defaultValue string) string {
	pair, _, err := kv.Get(key, nil)
	if err != nil || pair == nil {
		log.Printf("Consul'dan '%s' anahtarı okunamadı, varsayılan değer kullanılıyor.", key)
		return defaultValue
	}
	return string(pair.Value)
}

func startMessageConsumer(db *sql.DB, kv *api.KV) {
	// Bu fonksiyon artık sonsuz bir döngü içinde çalışacak ve bağlantı koptuğunda yeniden bağlanmayı deneyecek.
	for {
		rmqHost := getConfig(kv, "config/rabbitmq/host", "rabbitmq")
		rmqPort := getConfig(kv, "config/rabbitmq/port", "5672")
		rmqAddr := fmt.Sprintf("amqp://guest:guest@%s:%s/", rmqHost, rmqPort)

		conn, err := amqp.Dial(rmqAddr)
		if err != nil {
			log.Printf("RabbitMQ'ya bağlanamadı, 5 saniye sonra tekrar denenecek: %s", err)
			time.Sleep(5 * time.Second)
			continue // Döngünün başına dön ve tekrar dene
		}
		defer conn.Close()

		ch, err := conn.Channel()
		if err != nil {
			log.Printf("RabbitMQ kanalı açılamadı, 5 saniye sonra tekrar denenecek: %s", err)
			time.Sleep(5 * time.Second)
			continue
		}
		defer ch.Close()

		q, err := ch.QueueDeclare("clicks", true, false, false, false, nil)
		if err != nil {
			log.Printf("Kuyruk oluşturulamadı: %s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		msgs, err := ch.Consume(
			q.Name, // queue
			"",     // consumer
			false,  // auto-ack
			false,  // exclusive
			false,  // no-local
			false,  // no-wait
			nil,    // args
		)
		if err != nil {
			log.Printf("Mesajlar tüketilemedi: %s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf(" [*] %s kuyruğu dinleniyor...", q.Name)

		for d := range msgs {
			var event ClickEvent
			if err := json.Unmarshal(d.Body, &event); err != nil {
				log.Printf("Mesaj parse edilemedi (bozuk mesaj): %s", err)
				d.Ack(false)
				continue
			}

			event.MessageID = d.MessageId
			if event.MessageID == "" {
				log.Println("Uyarı: Gelen mesajın bir MessageID'si yok. İşleniyor ama tekrarlanabilir.")
			}

			log.Printf("Tıklama alındı: %s, MessageID: %s", event.ShortCode, event.MessageID)

			_, err = db.Exec("INSERT INTO clicks (short_code, message_id) VALUES ($1, $2)", event.ShortCode, event.MessageID)
			if err != nil {
				// Hatanın "unique_violation" olup olmadığını kontrol et
				if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
					log.Printf("Mükerrer mesaj tespit edildi (MessageID: %s). Mesaj atlanıyor.", event.MessageID)
					// Bu mesajı zaten işlemişiz. Tekrar denemenin anlamı yok. Başarıyla işlenmiş gibi onaylayıp kuyruktan sil.
					d.Ack(false)
				} else {
					// Başka bir veritabanı hatası (örn: bağlantı kopması)
					log.Printf("Veritabanına yazılamadı, mesaj yeniden kuyruğa eklenecek: %s", err)
					d.Nack(false, true)
				}
			} else {
				// İşlem başarılı. Mesajı onaylayıp kuyruktan siliyoruz.
				d.Ack(false)
			}
		}

		log.Println("Tüketici döngüsü sona erdi, yeniden başlatılıyor.")
		time.Sleep(5 * time.Second)
	}
}

func main() {

	consulConfig := api.DefaultConfig()
	consulConfig.Address = "consul:8500" // Docker içindeki adres
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		log.Fatalf("Consul istemcisi oluşturulamadı: %v", err)
	}
	kv := consulClient.KV()

	dbUser := getConfig(kv, "config/postgres/user", "postgres")
	dbPassword := getConfig(kv, "config/postgres/password", "")
	dbName := getConfig(kv, "config/postgres/dbname", "analytics_db")

	dbHost := "postgres"
	dbPort := "5432"

	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		dbUser, dbPassword, dbName, dbHost, dbPort)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("PostgreSQL'e bağlanamadı: %s", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("PostgreSQL'e ping atılamadı: %s", err)
	}
	log.Println("PostgreSQL'e başarıyla bağlanıldı.")

	registration := &api.AgentServiceRegistration{
		ID:      "analytics-service-1",
		Name:    "analytics-service",
		Port:    8081,
		Address: "analytics-service",
	}

	err = consulClient.Agent().ServiceRegister(registration)
	if err != nil {
		log.Fatalf("Servis Consul'a kaydedilemedi: %v", err)
	}
	log.Println("Servis başarıyla Consul'a kaydedildi.")

	// RabbitMQ dinleyicisini arka planda bir goroutine olarak başlatıyoruz. Bu sayede programın ana akışı web sunucusunu çalıştırmaya devam eder.
	go startMessageConsumer(db, kv)

	// Gin web sunucu
	router := gin.Default()
	router.GET("/analytics/:shortCode", func(c *gin.Context) {
		shortCode := c.Param("shortCode")

		var totalClicks int64
		// Toplam tıklanma sayısını sayan sorgu
		err := db.QueryRow("SELECT COUNT(id) FROM clicks WHERE short_code = $1", shortCode).Scan(&totalClicks)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Veri çekilemedi."})
			return
		}

		// Son 10 tıklanma zamanını çeken sorgu
		rows, err := db.Query("SELECT clicked_at FROM clicks WHERE short_code = $1 ORDER BY clicked_at DESC LIMIT 10", shortCode)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Veri çekilemedi."})
			return
		}
		defer rows.Close()

		var recentClicks []time.Time
		for rows.Next() {
			var clickedAt time.Time
			if err := rows.Scan(&clickedAt); err != nil {
				log.Printf("Satır okunamadı: %s", err)
				continue
			}
			recentClicks = append(recentClicks, clickedAt)
		}

		result := AnalyticsResult{
			TotalClicks:  totalClicks,
			RecentClicks: recentClicks,
		}

		c.JSON(http.StatusOK, result)
	})

	// Web sunucusunu 8081 portunda başlat.
	// Bu, ana programı çalışır halde tutar ve RabbitMQ dinleyicisi arka planda devam eder.
	router.Run(":8081")
}
