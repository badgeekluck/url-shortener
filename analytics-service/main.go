package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/streadway/amqp"
)

type ClickEvent struct {
	ShortCode string `json:"short_code"`
}

type AnalyticsResult struct {
	TotalClicks  int64       `json:"total_clicks"`
	RecentClicks []time.Time `json:"recent_clicks"`
}

func startMessageConsumer(db *sql.DB) {
	rmqHost := os.Getenv("RABBITMQ_HOST")
	rmqPort := os.Getenv("RABBITMQ_PORT")
	rmqAddr := fmt.Sprintf("amqp://guest:guest@%s:%s/", rmqHost, rmqPort)

	conn, err := amqp.Dial(rmqAddr)
	if err != nil {
		log.Fatalf("RabbitMQ'ya bağlanamadı: %s", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Kanal açılamadı: %s", err)
	}
	defer ch.Close()

	q, err := ch.QueueDeclare("clicks", true, false, false, false, nil)
	if err != nil {
		log.Fatalf("Kuyruk oluşturulamadı: %s", err)
	}

	msgs, err := ch.Consume(q.Name, "", true, false, false, false, nil)
	if err != nil {
		log.Fatalf("Mesajlar tüketilemedi: %s", err)
	}

	log.Printf(" [*] %s kuyruğu dinleniyor...", q.Name)

	// Gelen mesajları sonsuz bir döngüde işle
	for d := range msgs {
		var event ClickEvent
		if err := json.Unmarshal(d.Body, &event); err != nil {
			log.Printf("Mesaj parse edilemedi: %s", err)
			continue
		}
		log.Printf("Tıklama alındı: %s", event.ShortCode)

		_, err := db.Exec("INSERT INTO clicks (short_code) VALUES ($1)", event.ShortCode)
		if err != nil {
			log.Printf("Veritabanına yazılamadı: %s", err)
		}
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Uyarı: .env dosyası bulunamadı.")
	}
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"))

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("PostgreSQL'e bağlanamadı: %s", err)
	}
	defer db.Close()
	log.Println("PostgreSQL'e başarıyla bağlanıldı.")

	// RabbitMQ dinleyicisini arka planda bir goroutine olarak başlatıyoruz.
	// Bu sayede programın ana akışı web sunucusunu çalıştırmaya devam edebilir.
	go startMessageConsumer(db)

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
