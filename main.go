package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Listen string `yaml:"listen"`
	} `yaml:"server"`

	Monitor struct {
		Interval string `yaml:"interval"`
	} `yaml:"monitor"`

	Domains []string `yaml:"domains"`
}

type DomainStatus struct {
	Valid         bool   `json:"valid"`
	ValidTill     string `json:"valid_till"`
	LastCheck     string `json:"last_check"`
	DaysRemaining int    `json:"days_remaining"`
	Issuer        string `json:"issuer,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Error         string `json:"error,omitempty"`
}

type APIResponse struct {
	SSL struct {
		DomainsMonitored map[string]DomainStatus `json:"domains_monitored"`
	} `json:"ssl"`
}

type App struct {
	mu   sync.RWMutex
	data APIResponse
	cfg  Config
}

func main() {
	configPath := getEnv("CONFIG_FILE", "config.yaml")

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	interval, err := time.ParseDuration(cfg.Monitor.Interval)
	if err != nil {
		log.Fatalf("invalid interval: %v", err)
	}

	app := &App{
		cfg: cfg,
	}
	app.data.SSL.DomainsMonitored = make(map[string]DomainStatus)

	// eerste run direct
	app.runChecks()

	// scheduler
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			app.runChecks()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api", app.handleAPI)
	mux.HandleFunc("/healthz", handleHealth)

	log.Printf("monitoring %d domains", len(cfg.Domains))
	log.Printf("listening on %s", cfg.Server.Listen)

	log.Fatal(http.ListenAndServe(cfg.Server.Listen, mux))
}

func loadConfig(path string) (Config, error) {
	var cfg Config

	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("config not found, creating default: %s", path)

		defaultConfig := getDefaultConfig()

		data, err := yaml.Marshal(defaultConfig)
		if err != nil {
			return cfg, err
		}

		if err := os.WriteFile(path, data, 0644); err != nil {
			return cfg, err
		}

		log.Println("default config.yaml created")
		return defaultConfig, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func getDefaultConfig() Config {
	var cfg Config

	cfg.Server.Listen = ":8080"
	cfg.Monitor.Interval = "1h"

	cfg.Domains = []string{
		"example.com",
		"google.com",
	}

	return cfg
}

func (app *App) runChecks() {
	log.Println("running SSL checks")

	results := make(map[string]DomainStatus)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, domain := range app.cfg.Domains {
		d := domain
		wg.Add(1)

		go func() {
			defer wg.Done()

			status := checkDomain(d)

			mu.Lock()
			results[d] = status
			mu.Unlock()
		}()
	}

	wg.Wait()

	app.mu.Lock()
	app.data.SSL.DomainsMonitored = results
	app.mu.Unlock()
}

func checkDomain(domain string) DomainStatus {
	now := time.Now().UTC()

	status := DomainStatus{
		LastCheck: now.Format(time.RFC3339),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(domain, "443"), 10*time.Second)
	if err != nil {
		status.Error = fmt.Sprintf("tcp failed: %v", err)
		return status
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: domain,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		status.Error = fmt.Sprintf("tls failed: %v", err)
		return status
	}
	defer tlsConn.Close()

	cs := tlsConn.ConnectionState()

	if len(cs.PeerCertificates) == 0 {
		status.Error = "no certificate"
		return status
	}

	cert := cs.PeerCertificates[0]

	status.ValidTill = cert.NotAfter.Format(time.RFC3339)
	status.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	status.Issuer = cert.Issuer.String()
	status.Subject = cert.Subject.String()

	// hostname check
	if err := cert.VerifyHostname(domain); err != nil {
		status.Error = err.Error()
		return status
	}

	// chain validation
	roots, err := x509.SystemCertPool()
	if err != nil {
		status.Error = err.Error()
		return status
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(cs.PeerCertificates); i++ {
		intermediates.AddCert(cs.PeerCertificates[i])
	}

	_, err = cert.Verify(x509.VerifyOptions{
		DNSName:       domain,
		Roots:         roots,
		Intermediates: intermediates,
	})

	if err != nil {
		status.Error = err.Error()
		return status
	}

	// expiry check
	if now.After(cert.NotAfter) {
		status.Error = "certificate expired"
		return status
	}

	status.Valid = true
	return status
}

func (app *App) handleAPI(w http.ResponseWriter, r *http.Request) {
	app.mu.RLock()
	defer app.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(app.data)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}
