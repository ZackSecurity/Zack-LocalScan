// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package lib

import (
	"Zack-LocalScan/internal"
	"Zack-LocalScan/pkg/slog"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dnslog.org - the OOB callback platform used to verify blind vulnerabilities
// (SSRF / blind RCE / XXE / ...). API flow:
//
//	POST /new_gen  body: domain=<base>  -> {"domain":"<key>.<base>","key":"...","token":"..."}
//	POST /<token>  body: domain=<base>  -> {"0":{"ip":"...","subdomain":"...","time":"..."}, ...}
const (
	dnslogAPI        = "https://dnslog.org"
	dnslogBaseDomain = "log.nat.cloudns.ph."
)

// Platform requests must fail fast so a dead OOB channel cannot stall a scan.
// new_gen alone gets a longer timeout: it is the run's only chance to open the OOB
// channel, and the cold TLS handshake to the platform occasionally exceeds 3s
// (measured 1.4-2.4s slow path), which would silently disable every
// reverse-dependent rule for the whole run.
var (
	dnslogHTTPClient       = &http.Client{Timeout: 3 * time.Second}
	dnslogNewGenHTTPClient = &http.Client{Timeout: 5 * time.Second}
)

// The session issued by /new_gen is cached for the process lifetime; a failed request
// is not cached, so the next call retries.
var (
	dnslogMu     sync.Mutex
	dnslogDomain string // e.g. "03d96a95.log.nat.cloudns.ph."
	dnslogToken  string
)

// oobReady is written by OOBSelfTest before PoCs run and read concurrently by every
// PoC whose set contains newReverse().
var oobReady atomic.Bool

type dnslogGenResp struct {
	Domain string `json:"domain"`
	Key    string `json:"key"`
	Token  string `json:"token"`
}

type dnslogRecord struct {
	IP        string `json:"ip"`
	Subdomain string `json:"subdomain"`
	Time      string `json:"time"`
}

// getDnslogSession returns the assigned callback domain and query token, requesting
// a new session on first use.
func getDnslogSession() (domain, token string) {
	dnslogMu.Lock()
	defer dnslogMu.Unlock()
	if dnslogDomain != "" && dnslogToken != "" {
		return dnslogDomain, dnslogToken
	}

	data, err := dnslogPost(dnslogNewGenHTTPClient, "/new_gen")
	if err != nil {
		slog.Println(slog.DEBUG, "[-] dnslog new_gen error:", err)
		return "", ""
	}
	var gen dnslogGenResp
	if err := json.Unmarshal(data, &gen); err != nil {
		slog.Println(slog.DEBUG, "[-] dnslog new_gen bad response:", string(data))
		return "", ""
	}
	if gen.Domain == "" && gen.Key != "" {
		gen.Domain = gen.Key + "." + dnslogBaseDomain
	}
	if gen.Domain == "" || gen.Token == "" {
		slog.Println(slog.DEBUG, "[-] dnslog new_gen incomplete response:", string(data))
		return "", ""
	}

	dnslogDomain, dnslogToken = gen.Domain, gen.Token
	return dnslogDomain, dnslogToken
}

// newCallback generates a random callback label and its full host under the session
// domain, e.g. "a8f3k2m1.03d96a95.log.nat.cloudns.ph". Shared by the self-test and real
// PoCs so the two implementations cannot drift apart.
func newCallback() (sub, host, token string) {
	domain, token := getDnslogSession()
	if domain == "" || token == "" {
		return "", "", ""
	}
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	sub = RandomCryptoStr(letters, 8)
	host = fmt.Sprintf("%s.%s", sub, strings.TrimSuffix(domain, "."))
	return sub, host, token
}

// OOBSelfTest verifies the dnslog.org channel end to end: request a session domain,
// resolve a random label under it locally, then confirm the callback in the platform
// log. Must run once before PoCs; on failure newReverse() returns an empty Reverse.
func OOBSelfTest() bool {
	if !internal.Setting.DnsLog {
		return false
	}
	sub, host, token := newCallback()
	if host == "" || token == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
		slog.Println(slog.DEBUG, "[-] OOB self-test DNS resolution failed:", err)
		return false
	}

	// Give the platform a moment to record the query, then poll the log once.
	time.Sleep(2 * time.Second)
	if dnslogHit(token, sub) {
		oobReady.Store(true)
		return true
	}
	slog.Println(slog.DEBUG, "[-] OOB self-test callback not found in platform log:", host)
	return false
}

// dnslogHit reports whether the platform received a callback containing the given random label.
func dnslogHit(token, sub string) bool {
	data, err := dnslogPost(dnslogHTTPClient, "/"+token)
	if err != nil {
		slog.Println(slog.DEBUG, "[-] dnslog query error:", err)
		return false
	}
	var records map[string]dnslogRecord
	if err := json.Unmarshal(data, &records); err != nil {
		slog.Println(slog.DEBUG, "[-] dnslog query bad response:", string(data))
		return false
	}
	for _, rec := range records {
		if strings.Contains(rec.Subdomain, sub) {
			slog.Println(slog.DEBUG, "dnslog hit:", rec.Subdomain)
			return true
		}
	}
	return false
}

// dnslogPost sends one of the platform's form requests (the body always carries the
// base domain) and returns the body; non-2xx is an error, not an empty record.
func dnslogPost(client *http.Client, path string) ([]byte, error) {
	body := url.Values{"domain": {dnslogBaseDomain}}.Encode()
	req, err := http.NewRequest("POST", dnslogAPI+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", internal.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dnslog http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
