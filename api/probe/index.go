package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type ProbeResult struct {
	Domain string `json:"domain"`
	Port int `json:"port"`
	Status string `json:"status"`
	Error string `json:"error,omitempty"`
	SubjectCN string `json:"subjectCN,omitempty"`
	Issuer string `json:"issuer,omitempty"`
	NotBefore *time.Time `json:"notBefore,omitempty"`
	NotAfter *time.Time `json:"notAfter,omitempty"`
	DaysRemaining int `json:"daysRemaining"`
	SANs []string `json:"sans,omitempty"`
	TLSVersion string `json:"tlsVersion,omitempty"`
	CipherSuite string `json:"cipherSuite,omitempty"`
	ResolvedIPs []string `json:"resolvedIPs,omitempty"`
	DNSMs int64 `json:"dnsMs"`
	TCPMs int64 `json:"tcpMs"`
	TLSMs int64 `json:"tlsMs"`
	TotalMs int64 `json:"totalMs"`
	CheckedAt time.Time `json:"checkedAt"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost { w.Header().Set("Allow", "POST"); http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed); return }
	var req struct { Domains []string `json:"domains"`; TimeoutMs int `json:"timeoutMs"`; WarningDays int `json:"warningDays"` }
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, `{"error":"Invalid JSON body"}`, http.StatusBadRequest); return }
	if len(req.Domains) == 0 || len(req.Domains) > 20 { http.Error(w, `{"error":"Provide between 1 and 20 domains"}`, http.StatusBadRequest); return }
	if req.TimeoutMs == 0 { req.TimeoutMs = 6000 }; if req.TimeoutMs < 1000 || req.TimeoutMs > 10000 { http.Error(w, `{"error":"timeoutMs must be 1000–10000"}`, http.StatusBadRequest); return }
	if req.WarningDays == 0 { req.WarningDays = 30 }; if req.WarningDays < 1 || req.WarningDays > 365 { http.Error(w, `{"error":"warningDays must be 1–365"}`, http.StatusBadRequest); return }
	results := make([]ProbeResult, len(req.Domains))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, raw := range req.Domains {
		domain := strings.TrimSpace(strings.ToLower(raw))
		if strings.Contains(domain, ":") { domain = strings.Trim(domain, "[]") }
		wg.Add(1)
		go func(i int, host string) { defer wg.Done(); sem <- struct{}{}; defer func(){ <-sem }(); results[i] = probe(host, req.TimeoutMs, req.WarningDays) }(i, domain)
	}
	wg.Wait()
	sort.SliceStable(results, func(i,j int) bool { return results[i].Domain < results[j].Domain })
	_ = json.NewEncoder(w).Encode(map[string]any{"results":results, "checkedAt":time.Now().UTC(), "count":len(results)})
}

func probe(host string, timeoutMs, warningDays int) ProbeResult {
	start := time.Now()
	out := ProbeResult{Domain:host, Port:443, Status:"HANDSHAKE_ERROR", CheckedAt:time.Now().UTC()}
	fail := func(err error) ProbeResult { out.Error = err.Error(); out.TotalMs = time.Since(start).Milliseconds(); return out }
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@ ") { return fail(fmt.Errorf("Invalid hostname")) }
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond); defer cancel()
	t := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	out.DNSMs = time.Since(t).Milliseconds()
	if err != nil { return fail(fmt.Errorf("DNS lookup failed: %w", err)) }
	var public []netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP); if !ok { continue }; addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() { continue }
		public = append(public, addr); out.ResolvedIPs = append(out.ResolvedIPs, addr.String())
	}
	if len(public) == 0 { return fail(fmt.Errorf("No public IP addresses returned by DNS")) }
	dialer := net.Dialer{Timeout:time.Duration(timeoutMs)*time.Millisecond}
	address := net.JoinHostPort(public[0].String(), "443")
	t = time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	out.TCPMs = time.Since(t).Milliseconds()
	if err != nil { return fail(fmt.Errorf("TCP connection failed: %w", err)) }
	t = time.Now()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	err = tlsConn.HandshakeContext(ctx)
	out.TLSMs = time.Since(t).Milliseconds()
	if err != nil {
		_ = conn.Close()
		out.TotalMs = time.Since(start).Milliseconds()
		if strings.Contains(strings.ToLower(err.Error()), "expired") {
			out.Status = "EXPIRED"
		}
		return fail(fmt.Errorf("TLS handshake failed: %w", err))
	}
	defer tlsConn.Close()
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 { return fail(fmt.Errorf("Peer did not present a certificate")) }
	cert := state.PeerCertificates[0]
	now := time.Now()
	out.SubjectCN, out.Issuer = cert.Subject.CommonName, cert.Issuer.CommonName
	out.NotBefore, out.NotAfter = &cert.NotBefore, &cert.NotAfter
	out.DaysRemaining = int(time.Until(cert.NotAfter).Hours()/24)
	out.SANs = append([]string(nil), cert.DNSNames...)
	out.TLSVersion, out.CipherSuite = tlsVersion(state.Version), tls.CipherSuiteName(state.CipherSuite)
	switch { case now.After(cert.NotAfter): out.Status="EXPIRED"; case out.DaysRemaining <= warningDays: out.Status="EXPIRING_SOON"; default: out.Status="HEALTHY" }
	out.TotalMs = time.Since(start).Milliseconds()
	return out
}
func tlsVersion(v uint16) string { switch v { case tls.VersionTLS13:return "TLS 1.3"; case tls.VersionTLS12:return "TLS 1.2"; case tls.VersionTLS11:return "TLS 1.1"; default:return fmt.Sprintf("TLS 0x%04x",v) } }
