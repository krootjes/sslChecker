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
	"strings"
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
	ValidTill     string `json:"valid_till,omitempty"`
	LastCheck     string `json:"last_check"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
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
		log.Fatalf("invalid interval %q: %v", cfg.Monitor.Interval, err)
	}

	app := &App{
		cfg: cfg,
	}
	app.data.SSL.DomainsMonitored = make(map[string]DomainStatus)

	app.runChecks()

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

	server := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

func loadConfig(path string) (Config, error) {
	var cfg Config

	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("config not found, creating default config: %s", path)

		defaultCfg := getDefaultConfig()

		data, err := yaml.Marshal(defaultCfg)
		if err != nil {
			return cfg, err
		}

		if err := os.WriteFile(path, data, 0644); err != nil {
			return cfg, err
		}

		log.Printf("default config created: %s", path)
		return defaultCfg, nil
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
		"nepgroup.com",
		"nepworldwide.nl",
	}
	return cfg
}

func (app *App) runChecks() {
	log.Println("running SSL checks")

	results := make(map[string]DomainStatus)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, domain := range app.cfg.Domains {
		domain := domain

		wg.Add(1)
		go func() {
			defer wg.Done()

			status := checkDomain(domain)

			mu.Lock()
			results[domain] = status
			mu.Unlock()
		}()
	}

	wg.Wait()

	app.mu.Lock()
	app.data.SSL.DomainsMonitored = results
	app.mu.Unlock()

	log.Println("SSL checks finished")
}

func checkDomain(domain string) DomainStatus {
	now := time.Now().UTC()

	status := DomainStatus{
		Valid:     false,
		LastCheck: now.Format(time.RFC3339),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		status.Error = fmt.Sprintf("host unreachable: %v", err)
		return status
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return status
	}
	defer tlsConn.Close()

	cs := tlsConn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return status
	}

	cert := cs.PeerCertificates[0]

	status.ValidTill = cert.NotAfter.UTC().Format(time.RFC3339)
	status.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	status.Issuer = cert.Issuer.String()
	status.Subject = cert.Subject.String()

	if err := cert.VerifyHostname(domain); err != nil {
		return status
	}

	if now.Before(cert.NotBefore.UTC()) {
		return status
	}
	if now.After(cert.NotAfter.UTC()) {
		return status
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return status
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(cs.PeerCertificates); i++ {
		intermediates.AddCert(cs.PeerCertificates[i])
	}

	verifyOpts := x509.VerifyOptions{
		DNSName:       domain,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}

	if _, err := cert.Verify(verifyOpts); err != nil {
		return status
	}

	status.Valid = true
	return status
}

func (app *App) handleAPI(w http.ResponseWriter, r *http.Request) {
	// 🔥 NIEUW: logging van API access
	clientIP := getClientIP(r)
	log.Printf("API request from %s %s %s", clientIP, r.Method, r.URL.Path)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	app.mu.RLock()
	defer app.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(app.data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func getClientIP(r *http.Request) string {
	// check X-Forwarded-For (reverse proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// fallback naar RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
