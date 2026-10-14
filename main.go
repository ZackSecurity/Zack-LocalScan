// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package main

import (
	"Zack-LocalScan/internal"
	"Zack-LocalScan/pkg/hydra"
	"Zack-LocalScan/pkg/misc"
	"Zack-LocalScan/pkg/osping"
	pocScan "Zack-LocalScan/pkg/pocscan"
	pocScanLib "Zack-LocalScan/pkg/pocscan/lib"
	"Zack-LocalScan/pkg/pool"
	"Zack-LocalScan/pkg/simplehttp"
	"Zack-LocalScan/pkg/slog"
	"Zack-LocalScan/pkg/stdio"
	"Zack-LocalScan/pkg/discover"
	"Zack-LocalScan/pkg/uri"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== CLI Flags ====================
var (
	flagNet      string
	flagPort     string
	flagDiscover bool
	flagNoCrack  bool
	flagNoPoc    bool
	flagPocFull  bool
	flagJobs     int
	flagWait     int
	flagFast     bool
	flagQuiet    bool
	flagOut      string
)

func init() {
	flag.Usage = printHelp

	flag.StringVar(&flagNet, "n", "", "")
	flag.StringVar(&flagNet, "net", "", "")
	flag.StringVar(&flagPort, "p", "", "")
	flag.StringVar(&flagPort, "port", "", "")
	flag.BoolVar(&flagDiscover, "d", false, "")
	flag.BoolVar(&flagDiscover, "discover", false, "")
	flag.BoolVar(&flagNoCrack, "nc", false, "")
	flag.BoolVar(&flagNoCrack, "nocrack", false, "")
	flag.BoolVar(&flagNoPoc, "np", false, "")
	flag.BoolVar(&flagNoPoc, "nopoc", false, "")
	flag.BoolVar(&flagPocFull, "pf", false, "")
	flag.BoolVar(&flagPocFull, "pocfull", false, "")
	flag.IntVar(&flagJobs, "j", 200, "")
	flag.IntVar(&flagJobs, "jobs", 200, "")
	flag.IntVar(&flagWait, "w", 2, "")
	flag.IntVar(&flagWait, "wait", 2, "")
	flag.BoolVar(&flagFast, "f", false, "")
	flag.BoolVar(&flagFast, "fast", false, "")
	flag.BoolVar(&flagQuiet, "q", false, "")
	flag.BoolVar(&flagQuiet, "quiet", false, "")
	flag.StringVar(&flagOut, "o", "report.txt", "")
	flag.StringVar(&flagOut, "out", "report.txt", "")
}

func printHelp() {
	fmt.Fprint(os.Stderr, `
  Zack-LocalScan v1.0 - Fast intranet scanner

Usage: zack-localscan (-n target | -d) [options]

  -n, --net  <target>   IP, CIDR, IP range or file path (one target per line)
  -d, --discover        Auto-detect reachable local private subnets
  -p, --port <ports>    Ports to scan, comma-separated or ranges (default: 15 common ports)
  -nc, --nocrack        Disable weak-credential brute force
  -np, --nopoc          Disable PoC vulnerability scan
  -pf, --pocfull        Full PoC mode: brute-force style PoCs (e.g. Shiro key) test all combos
  -j, --jobs  <n>       Concurrent workers (default: 200)
  -w, --wait  <sec>     Connection timeout in seconds (default: 2)
  -f, --fast            Skip host liveness check, scan ports directly
  -q, --quiet           Quiet mode: no terminal output
  -o, --out  <file>     Report file (default: report.txt)

Examples:
  zack-localscan -n 192.168.1.0/24                         # scan a subnet
  zack-localscan -n 192.168.1.1 -p 22,80,443               # specific ports
  zack-localscan -d                                        # auto-discover intranet
  zack-localscan -n 10.0.0.0/16 -nc -np                    # skip cracking and PoCs
  zack-localscan -n 192.168.1.0/24 -f -j 200 -o r.txt      # skip liveness + write file
  zack-localscan -n 192.168.1.0/24 -p 1-1000 -w 5          # port range + timeout
  zack-localscan -n 192.168.1.0/24 -q                      # quiet scan, results to file

`)
}

// ==================== Default Ports ====================
// 4 HTTP ports + 11 brute-force protocol ports
var DEFAULT_PORTS = []int{
	80, 443, 8080, 8443,
	21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 6379, 27017,
}

// ==================== Global State ====================
var (
	gPorts    []int
	gTimeout  time.Duration
	gOutFile  *os.File
	gStart    time.Time
	gPhaseT   time.Time // phase start time
)

// ==================== Result Types ====================
type httpFingerResult struct {
	url   string
	title string
}

type crackResult struct {
	target   string
	username string
	password string
}

// Result collectors
var (
	gAliveIPs     []net.IP
	gPortResults  []portResult
	gHTTPResults  []httpFingerResult
	gCrackResults []crackResult
	gResultMu     sync.Mutex
)

// ==================== Main ====================
func main() {
	flag.Parse()

	// Reject invalid -j/-w values: zero workers hangs the scan, zero timeout disables all deadlines.
	if flagJobs < 1 {
		slog.Printf(slog.ERROR, "-j/--jobs must be greater than 0 (got %d)", flagJobs)
	}
	if flagWait < 1 {
		slog.Printf(slog.ERROR, "-w/--wait must be greater than 0 (got %d)", flagWait)
	}

	stdio.SetQuiet(flagQuiet)
	slog.SetLevel(slog.INFO)

	if flagPort != "" {
		gPorts = parsePorts(flagPort)
	} else {
		gPorts = DEFAULT_PORTS
	}

	gTimeout = time.Duration(flagWait) * time.Second
	osping.Timeout = flagWait

	if flagNet != "" && flagDiscover {
		slog.Println(slog.ERROR, "-n and -d are mutually exclusive")
		os.Exit(1)
	}

	var allTargets []string
	if flagDiscover {
		allTargets = runDiscover()
		if len(allTargets) == 0 {
			return
		}
	} else if flagNet != "" {
		allTargets = parseTargetList(flagNet)
	}

	if len(allTargets) == 0 {
		flag.Usage()
		return
	}

	// Open report file
	reportF, err := os.OpenFile(flagOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		slog.Printf(slog.ERROR, "cannot open report file: %v", err)
		os.Exit(1)
	}
	gOutFile = reportF
	defer reportF.Close()

	initEngines()
	runScan(allTargets)
}

// ==================== Port Parsing ====================
func parsePorts(s string) []int {
	var ports []int
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				slog.Printf(slog.WARN, "skip invalid port range: %s", part)
				continue
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				slog.Printf(slog.WARN, "skip invalid port: %s", part)
				continue
			}
			ports = append(ports, p)
		}
	}
	return misc.RemoveDuplicateElement(ports)
}

// ==================== Discover Mode ====================
func runDiscover() []string {
	subnets := discover.GetAllSubnets()
	if len(subnets) == 0 {
		slog.Println(slog.WARN, "[discover] no local private subnet found, specify targets with -n")
		return nil
	}

	slog.Printf(slog.INFO, "[discover] found %d local private subnets:", len(subnets))
	var targets []string
	for _, s := range subnets {
		slog.Printf(slog.DATA, "  %-18s (%s)", s.CIDR, s.Source)
		targets = append(targets, s.CIDR)
	}

	return targets
}

// ==================== Scan Pipeline ====================
func runScan(targets []string) {
	gStart = time.Now()

	var scanIPs []net.IP
	for _, t := range targets {
		scanIPs = append(scanIPs, resolveTarget(t)...)
	}
	if len(scanIPs) == 0 {
		slog.Println(slog.ERROR, "no scannable IP")
		return
	}
	scanIPs = misc.RemoveDuplicateElement(scanIPs)

	slog.Printf(slog.INFO, "Targets: %d IPs | %d ports | j=%d w=%ds",
		len(scanIPs), len(gPorts), flagJobs, flagWait)

	// Init report header
	writeReportHeader()

	// ── Step 1: Liveness ──
	gPhaseT = time.Now()
	aliveIPs := phaseLiveness(scanIPs)
	gAliveIPs = aliveIPs
	flushReportLiveness()
	if len(aliveIPs) == 0 {
		slog.Println(slog.INFO, "no live host")
		writeReportSummary()
		return
	}

	// ── Step 2: Port scan ──
	gPhaseT = time.Now()
	httpTargets, crackTargets := phasePortScan(aliveIPs)
	flushReportPortScan()

	// ── Steps 3+4+5: serial ──
	hasHTTP := len(httpTargets) > 0
	hasCrack := !flagNoCrack && len(crackTargets) > 0

	var webOK []httpTarget
	if hasHTTP {
		gPhaseT = time.Now()
		webOK = phaseHTTPFinger(httpTargets)
		flushReportWeb()
	}

	hasPoc := !flagNoPoc && len(webOK) > 0
	if hasPoc {
		gPhaseT = time.Now()
		phaseWebPoC(webOK)
		flushReportPoC()
	}

	if hasCrack {
		gPhaseT = time.Now()
		phaseHydra(crackTargets)
		flushReportCrack()
	}

	internal.PocResultsMu.Lock()
	pocN := len(internal.PocResults)
	internal.PocResultsMu.Unlock()
	elapsed := time.Since(gStart).Round(time.Millisecond)
	slog.Printf(slog.INFO, "Done: %v | %d alive | %d ports | %d web | %d poc | %d cracked",
		elapsed, len(aliveIPs), len(gPortResults), len(gHTTPResults),
		pocN, len(gCrackResults))

	writeReportSummary()
}

// ─── Phase Helpers ───

func waitPoolDone(p *pool.Pool) {
	for !p.Done.Load() || p.RunningThreads() > 0 {
		time.Sleep(time.Millisecond * 200)
	}
}

// parallelFor runs fn over items with at most flagJobs concurrency; the semaphore is
// acquired before spawning each goroutine, so huge target lists cannot flood the runtime.
func parallelFor[T any](items []T, fn func(T)) {
	sem := make(chan struct{}, flagJobs)
	var wg sync.WaitGroup
	for _, item := range items {
		sem <- struct{}{}
		wg.Add(1)
		go func(item T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(item)
		}(item)
	}
	wg.Wait()
}

func phaseLiveness(scanIPs []net.IP) []net.IP {
	if flagFast {
		slog.Println(slog.INFO, "[1] Liveness  skipped (-f)")
		return scanIPs
	}

	slog.Printf(slog.INFO, "[1] Liveness  %d IPs...", len(scanIPs))

	p := pool.New(flagJobs)
	var alive []net.IP
	var mu sync.Mutex

	p.Function = func(in interface{}) {
		ip := in.(net.IP)
		if osping.Ping(ip.String()) {
			mu.Lock()
			alive = append(alive, ip)
			mu.Unlock()
			slog.Println(slog.DATA, "  "+ip.String())
		}
	}

	go p.Run()
	go func() {
		for _, ip := range scanIPs {
			p.Push(ip)
		}
		p.Stop()
	}()
	waitPoolDone(p)

	slog.Printf(slog.INFO, "  -> %d/%d alive (%.1fs)",
		len(alive), len(scanIPs), time.Since(gPhaseT).Seconds())
	return alive
}

// ─── Phase 2 Types ───

type httpTarget struct {
	ip     net.IP
	port   int
	scheme string
}

type crackTarget struct {
	ip       net.IP
	port     int
	protocol string
}

type portResult struct {
	target string
	port   string
}

type portJob struct {
	ip   net.IP
	port int
}

// httpPorts maps port -> scheme for HTTP routing.
var httpPorts = map[int]string{
	80:   "http",
	443:  "https",
	8080: "http",
	8443: "https",
}

func phasePortScan(aliveIPs []net.IP) (httpTargets []httpTarget, crackTargets []crackTarget) {
	slog.Printf(slog.INFO, "[2] Port scan  %d hosts x %d ports...", len(aliveIPs), len(gPorts))

	p := pool.New(flagJobs)
	p.Interval = time.Millisecond * 5
	var results []portResult
	var resMu sync.Mutex

	p.Function = func(in interface{}) {
		job := in.(portJob)
		target := net.JoinHostPort(job.ip.String(), strconv.Itoa(job.port))
		conn, err := net.DialTimeout("tcp", target, gTimeout)
		if err == nil {
			conn.Close()

			resMu.Lock()
			portStr := strconv.Itoa(job.port)
			results = append(results, portResult{target: target, port: portStr})
			slog.Println(slog.DATA, fmt.Sprintf("  %-21s %-5s open", target, portStr))

			// Route to HTTP fingerprint
			if scheme, ok := httpPorts[job.port]; ok {
				httpTargets = append(httpTargets, httpTarget{job.ip, job.port, scheme})
			}

			// Route to brute force (port-number-based)
			if hydraProto := knownPortToHydraProto(job.port); hydraProto != "" {
				crackTargets = append(crackTargets, crackTarget{job.ip, job.port, hydraProto})
			}
			resMu.Unlock()
		}
	}

	go p.Run()
	go func() {
		for _, ip := range aliveIPs {
			for _, port := range gPorts {
				p.Push(portJob{ip, port})
			}
		}
		p.Stop()
	}()
	waitPoolDone(p)

	gResultMu.Lock()
	gPortResults = append(gPortResults, results...)
	gResultMu.Unlock()

	slog.Printf(slog.INFO, "  -> %d open | HTTP:%d | Crack:%d (%.1fs)",
		len(results), len(httpTargets), len(crackTargets), time.Since(gPhaseT).Seconds())
	return
}

// ─── Phase 3: HTTP Fingerprint ───

func phaseHTTPFinger(targets []httpTarget) []httpTarget {
	slog.Printf(slog.INFO, "[3] Web title  %d targets...", len(targets))

	var successful []httpTarget
	var successMu sync.Mutex
	parallelFor(targets, func(t httpTarget) {
		if doWebTitle(t.ip, t.port, t.scheme) {
			successMu.Lock()
			successful = append(successful, t)
			successMu.Unlock()
		}
	})
	slog.Printf(slog.INFO, "  -> %d (%.1fs)", len(successful), time.Since(gPhaseT).Seconds())
	return successful
}

// ─── Phase 4: PoC ───

func phaseWebPoC(targets []httpTarget) {
	slog.Printf(slog.INFO, "[4] PoC scan  %d targets...", len(targets))

	// OOB (DNSLog) self-test: decides whether reverse-dependent rules are usable.
	if pocScanLib.OOBSelfTest() {
		slog.Println(slog.INFO, "  OOB self-test passed, dnslog.org is up")
	} else {
		slog.Println(slog.WARN, "  OOB self-test failed, reverse-dependent rules will be skipped")
	}

	parallelFor(targets, func(t httpTarget) {
		urlStr := fmt.Sprintf("%s://%s:%d", t.scheme, t.ip.String(), t.port)
		info := &internal.HostInfo{
			Host:  t.ip.String(),
			Ports: strconv.Itoa(t.port),
			Url:   urlStr,
		}
		if err := pocScan.WebTitle(info); err != nil {
			slog.Println(slog.DEBUG, "PoC:", info.Url, err)
		}
	})
	internal.PocResultsMu.Lock()
	pocN := len(internal.PocResults)
	internal.PocResultsMu.Unlock()
	slog.Printf(slog.INFO, "  -> %d found (%.1fs)",
		pocN, time.Since(gPhaseT).Seconds())
}

// ─── Phase 5: Brute Force ───

// hydraThreads: per-target parallel auth attempts — NOT controlled by -j.
// Each protocol has a safe limit based on server-side connection tolerance.
var hydraThreads = map[string]int{
	"ssh": 10, "redis": 10, "ftp": 10,
	"mysql": 10, "mssql": 10, "postgresql": 10,
	"oracle": 5, "mongodb": 10,
	"smb": 5, "rdp": 3, "telnet": 5,
}

func phaseHydra(targets []crackTarget) {
	slog.Printf(slog.INFO, "[5] Brute force  %d targets...", len(targets))

	var cracked int32
	parallelFor(targets, func(t crackTarget) {
		threads := hydraThreads[t.protocol]
		if threads == 0 {
			threads = 5
		}
		info := hydra.NewAuthInfo(t.ip.String(), t.port, t.protocol)
		cracker := hydra.NewCracker(info, threads)
		cracker.Retries(1)
		auth, err := cracker.Run()
		if err == nil && auth != nil {
			atomic.AddInt32(&cracked, 1)
			handleCrackSuccess(t.ip, t.port, t.protocol, auth)
		}
	})
	slog.Printf(slog.INFO, "  -> %d cracked (%.1fs)",
		cracked, time.Since(gPhaseT).Seconds())
}

// ==================== Target Parsing ====================
func parseTargetList(expr string) []string {
	if expr == "" {
		return nil
	}
	if !uri.IsIPv4(expr) && !uri.IsCIDR(expr) && !uri.IsIPRanger(expr) {
		data, err := os.ReadFile(expr)
		if err == nil {
			var targets []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					targets = append(targets, line)
				}
			}
			if len(targets) > 0 {
				return targets
			}
		}
	}
	return []string{expr}
}

func resolveTarget(target string) []net.IP {
	if uri.IsIPv4(target) {
		return []net.IP{net.ParseIP(target)}
	}
	if uri.IsCIDR(target) {
		ips := uri.CIDRToIP(target)
		if len(ips) == 0 {
			// Ranges larger than 65536 IPs expand to an empty list - warn instead of dropping silently.
			slog.Printf(slog.WARN, "skip: %s (exceeds the 65536 IPs per target limit)", target)
		}
		return ips
	}
	if uri.IsIPRanger(target) {
		ips := uri.RangerToIP(target)
		if len(ips) == 0 {
			slog.Printf(slog.WARN, "skip: %s (exceeds the 65536 IPs per target limit)", target)
		}
		return ips
	}
	slog.Printf(slog.WARN, "skip: %s", target)
	return nil
}

// ==================== Engine Init ====================
func initEngines() {
	internal.Setting.PocNum = 20
	internal.Setting.PocFull = flagPocFull
	internal.Setting.WebTimeout = flagWait
	internal.Args.Timeout = flagWait
	pocScanLib.Inithttp()
}

// ==================== Handlers ====================
func handleCrackSuccess(ip net.IP, port int, protocol string, auth *hydra.Auth) {
	target := fmt.Sprintf("%s://%s:%d", protocol, ip.String(), port)
	var creds string
	if auth.Username != "" {
		creds = auth.Username + ":" + auth.Password
	} else {
		creds = auth.Password
	}

	gResultMu.Lock()
	gCrackResults = append(gCrackResults, crackResult{target, auth.Username, auth.Password})
	gResultMu.Unlock()

	slog.Printf(slog.DATA, "  %-30s %s", target, creds)
}

// ==================== HTTP Fingerprint ====================
func doWebTitle(ip net.IP, port int, scheme string) bool {
	rawURL := fmt.Sprintf("%s://%s:%d", scheme, ip.String(), port)

	httpClient := simplehttp.NewClientWithTimeout(gTimeout)
	req, err := simplehttp.NewRequest("GET", rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", simplehttp.RandomUserAgent())
	resp, _ := simplehttp.Do(httpClient, req)
	if resp == nil {
		return false
	}
	// When only the 2s body read times out, resp is still usable - discarding it would drop
	// the host from both the [Web] report and the PoC phase.
	_, body := simplehttp.SplitHeaderAndBody(resp.Raw.String())
	title := extractTitle(body)
	if title == "" {
		title = "-"
	}
	statusCode := strconv.Itoa(resp.StatusCode)

	slog.Println(slog.DATA, fmt.Sprintf("  %-30s %s  %s",
		rawURL, statusCode, truncate(title, 24)))

	gResultMu.Lock()
	gHTTPResults = append(gHTTPResults, httpFingerResult{
		url:   rawURL,
		title: title,
	})
	gResultMu.Unlock()
	return true
}

// ==================== Output Helpers ====================

// knownPortToHydraProto maps IANA well-known port numbers to hydra protocol names.
func knownPortToHydraProto(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 445:
		return "smb"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	}
	return ""
}

func ipLess(a, b net.IP) bool {
	ai, bj := a.To4(), b.To4()
	if ai == nil || bj == nil {
		return a.String() < b.String()
	}
	for i := 0; i < 4; i++ {
		if ai[i] != bj[i] {
			return ai[i] < bj[i]
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
}

var titleRe = regexp.MustCompile(`<title[^>]*>([^<]*)</title>`)

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// ==================== Report Writer ====================

func writeReportHeader() {
	if gOutFile == nil {
		return
	}
	fmt.Fprintf(gOutFile, "Zack-LocalScan v1.0  %s\n\n",
		time.Now().Format("2006-01-02 15:04:05"))
	gOutFile.Sync()
}

func flushReportLiveness() {
	if gOutFile == nil {
		return
	}
	if flagFast {
		fmt.Fprintf(gOutFile, "[Alive] skipped check for %d IPs\n\n", len(gAliveIPs))
	} else {
		fmt.Fprintf(gOutFile, "[Alive] %d alive\n", len(gAliveIPs))
		sortIPs := make([]net.IP, len(gAliveIPs))
		copy(sortIPs, gAliveIPs)
		sort.Slice(sortIPs, func(i, j int) bool { return ipLess(sortIPs[i], sortIPs[j]) })
		for _, ip := range sortIPs {
			fmt.Fprintf(gOutFile, "  %s\n", ip.String())
		}
		fmt.Fprintln(gOutFile)
	}
	gOutFile.Sync()
}

func flushReportPortScan() {
	if gOutFile == nil {
		return
	}
	fmt.Fprintf(gOutFile, "[Ports] %d open\n", len(gPortResults))
	if len(gPortResults) > 0 {
		sort.Slice(gPortResults, func(i, j int) bool {
			pi, _ := strconv.Atoi(gPortResults[i].port)
			pj, _ := strconv.Atoi(gPortResults[j].port)
			if pi != pj {
				return pi < pj
			}
			return gPortResults[i].target < gPortResults[j].target
		})
		for _, r := range gPortResults {
			fmt.Fprintf(gOutFile, "  %-30s %-5s open\n", r.target, r.port)
		}
	}
	fmt.Fprintln(gOutFile)
	gOutFile.Sync()
}

func flushReportWeb() {
	if gOutFile == nil || len(gHTTPResults) == 0 {
		return
	}
	fmt.Fprintf(gOutFile, "[Web] %d\n", len(gHTTPResults))
	sortWeb := make([]httpFingerResult, len(gHTTPResults))
	copy(sortWeb, gHTTPResults)
	sort.Slice(sortWeb, func(i, j int) bool { return sortWeb[i].url < sortWeb[j].url })
	for _, r := range sortWeb {
		fmt.Fprintf(gOutFile, "  %-30s %s\n", r.url, r.title)
	}
	fmt.Fprintln(gOutFile)
	gOutFile.Sync()
}

func flushReportPoC() {
	if gOutFile == nil {
		return
	}
	internal.PocResultsMu.Lock()
	pocResults := make([]string, len(internal.PocResults))
	copy(pocResults, internal.PocResults)
	internal.PocResultsMu.Unlock()
	if len(pocResults) > 0 {
		fmt.Fprintf(gOutFile, "[PoC] %d\n", len(pocResults))
		for _, r := range pocResults {
			fmt.Fprintln(gOutFile, r)
		}
		fmt.Fprintln(gOutFile)
	}
	gOutFile.Sync()
}

func flushReportCrack() {
	if gOutFile == nil || len(gCrackResults) == 0 {
		return
	}
	fmt.Fprintf(gOutFile, "[Weak creds] %d\n", len(gCrackResults))
	for _, c := range gCrackResults {
		creds := c.username
		if creds != "" {
			creds = c.username + ":" + c.password
		} else {
			creds = c.password
		}
		fmt.Fprintf(gOutFile, "  %-30s %s\n", c.target, creds)
	}
	fmt.Fprintln(gOutFile)
	gOutFile.Sync()
}

func writeReportSummary() {
	if gOutFile == nil {
		return
	}
	internal.PocResultsMu.Lock()
	pocN := len(internal.PocResults)
	internal.PocResultsMu.Unlock()
	elapsed := time.Since(gStart).Round(time.Millisecond)
	fmt.Fprintf(gOutFile, "Alive:%d | Ports:%d | Web:%d | PoC:%d | WeakCreds:%d | %v\n",
		len(gAliveIPs), len(gPortResults), len(gHTTPResults), pocN, len(gCrackResults), elapsed)
	gOutFile.Sync()
}
