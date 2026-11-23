package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Target struct {
	ID string `json:"id"`
	Domain string `json:"domain"`
	Port int `json:"port"`
	Environment string `json:"environment"`
	WarningDaysThreshold int `json:"warningDaysThreshold"`
}

var (
	targetMu sync.RWMutex
	targets = []Target{
		{ID: "safaricom-api", Domain: "api.safaricom.co.ke", Port: 443, Environment: "PRODUCTION", WarningDaysThreshold: 30},
		{ID: "github", Domain: "github.com", Port: 443, Environment: "EXTERNAL", WarningDaysThreshold: 30},
		{ID: "vercel", Domain: "vercel.com", Port: 443, Environment: "PRODUCTION", WarningDaysThreshold: 30},
		{ID: "badssl-expired", Domain: "expired.badssl.com", Port: 443, Environment: "TEST", WarningDaysThreshold: 30},
		{ID: "badssl-hostname", Domain: "wrong.host.badssl.com", Port: 443, Environment: "TEST", WarningDaysThreshold: 30},
	}
	hostPattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		targetMu.RLock()
		out := append([]Target(nil), targets...)
		targetMu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"targets": out, "engine": "active", "timestamp": time.Now().UTC()})
	case http.MethodPost:
		var input struct {
			Domain string `json:"domain"`
			Port int `json:"port"`
			Environment string `json:"environment"`
			WarningDays int `json:"warningDays"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, `{"error":"Invalid JSON body"}`, http.StatusBadRequest)
			return
		}
		input.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(input.Domain)), ".")
		if !hostPattern.MatchString(input.Domain) {
			http.Error(w, `{"error":"Enter a valid DNS hostname"}`, http.StatusBadRequest)
			return
		}
		if input.Port == 0 { input.Port = 443 }
		if input.Port < 1 || input.Port > 65535 {
			http.Error(w, `{"error":"Port must be between 1 and 65535"}`, http.StatusBadRequest)
			return
		}
		if input.WarningDays == 0 { input.WarningDays = 30 }
		if input.WarningDays < 1 || input.WarningDays > 365 {
			http.Error(w, `{"error":"Warning days must be between 1 and 365"}`, http.StatusBadRequest)
			return
		}
		if input.Environment == "" { input.Environment = "CUSTOM" }
		targetMu.Lock()
		for _, t := range targets {
			if t.Domain == input.Domain && t.Port == input.Port {
				targetMu.Unlock()
				http.Error(w, `{"error":"Target already exists"}`, http.StatusConflict)
				return
			}
		}
		t := Target{ID: input.Domain + ":" + strconv.Itoa(input.Port), Domain: input.Domain, Port: input.Port, Environment: input.Environment, WarningDaysThreshold: input.WarningDays}
		targets = append(targets, t)
		targetMu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"target": t})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
