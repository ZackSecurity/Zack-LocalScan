# Zack-LocalScan

**English** | [简体中文](README-CN.md)

**Zack-LocalScan** is an intranet penetration scanning tool written in Go. One command automatically
runs the whole pipeline — **host discovery → port scan → web title extraction → PoC vulnerability
verification → weak-credential brute force** — helping security teams quickly identify high-value
targets during lateral movement inside the intranet.

> **Disclaimer**
> This tool is intended for authorized security testing, red-team engagements and educational
> research only. You must have explicit written permission from the owner of any system you scan.
> Unauthorized scanning or attacking may be illegal in your jurisdiction.

## Build

Requires Go 1.25+ (older toolchains download it automatically via `GOTOOLCHAIN=auto`).

```bash
go build -o zack-localscan .
```

Cross-compile for three platforms:

```bash
./build.sh          # linux/amd64, windows/amd64, darwin/arm64 -> build/
.\build.ps1         # PowerShell equivalent (-NoClean keeps existing artifacts)
```

## Command line reference

```
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
```

![CLI help output](image/scan-result-linux-help.png)

## Usage scenarios

```bash
# First time in an intranet: discover and scan everything
zack-localscan -d -o initial_scan.txt

# Large-scale fast port scan
zack-localscan -n 10.0.0.0/16 -p 1-65535 -f -j 300 -w 2 -q -o full_port.txt

# Web-focused scan (no brute force)
zack-localscan -n web_assets.txt -p 80,443,8080,8443 -nc -o web_vuln.txt

# Credential audit (no PoCs, databases and remote admin ports only)
zack-localscan -n 192.168.1.0/24 -p 22,3389,3306,1433,6379 -np -o pass_audit.txt

# Single-host quick check
zack-localscan -n 10.0.1.100 -p 80,443,22,3306 -f -w 1 -j 50
```

![Subnet scan example](image/scan-result-linux.png)

*Demo output: simulated lab-environment data.*

## Core capabilities

### 1. Subnet auto-discovery (`-d`)

No need to know the network layout up front. `-d` gathers targets from:

- **NICs** — all local interface IPs, mapped to their private subnets (loopback and link-local excluded)
- **Routing tables** — `route print -4` on Windows, `/proc/net/route` on Linux, `netstat -rn` on macOS
- **Filtering** — RFC 1918 ranges only (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), deduplicated

![Auto-discovery scan example](image/scan-result-linux-discover.png)

*Demo output: simulated lab-environment data.*

### 2. Five-stage pipeline

| Stage | Function |
|-------|----------|
| **1. Liveness** | TCP probing (80/443/22/445) — a SYN-ACK or RST proves the host is up |
| **2. Port scan** | TCP connect, 15 common ports by default |
| **3. Web title** | HTTP GET + title extraction |
| **4. PoC scan** | 387 built-in PoC rules matched against every web target |
| **5. Brute force** | Concurrent weak-credential checks for 11 services |

**Skip controls:** `-f` (skip stage 1), `-np` (skip stage 4), `-nc` (skip stage 5).

### 3. PoC engine

387 PoC rules (xray YAML format), embedded in the binary at compile time:

| Target category | Rules | Typical targets |
|-----------------|-------|-----------------|
| OA / collaboration suites | 50+ | Seeyon, Weaver, Tongda, Landray, Yonyou, Kingdee |
| Java middleware | 45+ | WebLogic, Tomcat, JBoss, Solr, Nexus, Confluence, Jira, Jenkins |
| Network & security appliances | 40+ | Ruijie, Sangfor, H3C, Huawei, F5, Citrix, Topsec |
| Big data & DevOps | 40+ | Elasticsearch, Kibana, Hadoop, Druid, Nacos, Flink, Docker, K8s, Zabbix |
| Dev frameworks | 35+ | Spring Boot/Cloud/Gateway, ThinkPHP, Struts2, Shiro, Drupal, WordPress |
| CMS | 35+ | DedeCMS, Discuz, MetInfo, ZenTao, ECShop, SeaCMS |
| Remote management / bastion hosts | 15+ | JumpServer, VMware vSphere/ESXi, Hikvision |
| Others | 60+ | Unauthenticated databases, mail systems, backup files, directory traversal |

Advanced features:

- **CEL expression engine** — complex verification logic (e.g. send `print(A*B)`, extract the
  returned value and confirm it equals A×B for precise RCE confirmation)
- **DNSLog OOB verification** — blind SSRF / blind RCE / XXE via the [dnslog.org] platform,
  with an end-to-end self-test before the PoC phase
- **Groups** — one PoC may carry several detection rule sets; a hit in any group confirms

[dnslog.org]: https://dnslog.org

### 4. Brute force

11 protocols, a shared top-10 password dictionary, per-protocol usernames and special
credential combinations:

| Protocol | Port | Users | Combos | Concurrency |
|----------|------|-------|--------|-------------|
| SSH | 22 | 2 | 26 | 10 |
| RDP | 3389 | 2 | 21 | 3 |
| FTP | 21 | 2 | 22 | 10 |
| SMB | 445 | 2 | 21 | 5 |
| Telnet | 23 | 2 | 24 | 5 |
| MySQL | 3306 | 2 | 20 | 10 |
| MSSQL | 1433 | 2 | 20 | 10 |
| Oracle | 1521 | 2 | 25 | 5 |
| PostgreSQL | 5432 | 2 | 20 | 10 |
| Redis | 6379 | 1 | 10 | 10 |
| MongoDB | 27017 | 2 | 20 | 10 |

Stops at the first valid credential per target; Oracle discovers the SID automatically;
Telnet detects the authentication mode first.

### 5. Input & output

**Targets** (`-n` is auto-detected):

```
-n 192.168.1.1                  # single IP
-n 192.168.1.0/24               # CIDR
-n 192.168.1.1-255              # IP range (last octet)
-n 192.168.1.1-192.168.2.255    # full range
-n targets.txt                  # file, one target per line
```

**Ports**: `-p 80,443,8080` / `-p 1-1000` / `-p 22,80,8000-8080`

**Report** (default `report.txt`, override with `-o`):

```
Zack-LocalScan v1.0  2026-01-01 12:00:00

[Alive] 42 alive
  192.168.1.1
  192.168.1.10

[Ports] 23 open
  192.168.1.1:80              80    open
  192.168.1.1:443             443   open

[Web] 16
  http://192.168.1.1:80       Admin panel
  https://192.168.1.1:443     Spring Boot Admin

[PoC] 3
  http://192.168.1.1:8080     poc-yaml-spring-actuator-heapdump-file

[Weak creds] 2
  ssh://192.168.1.10:22       root:admin123
  mysql://192.168.1.30:3306   root:root

Alive:42 | Ports:23 | Web:16 | PoC:3 | WeakCreds:2 | 3m42s
```

`-q` quiet mode: no terminal output, the report file is still written.

## Project layout

| Path | Purpose |
|------|---------|
| `main.go` | CLI, five-phase pipeline, report writer |
| `pkg/pocscan/` | PoC engine: embedded xray-format YAML rules (`pocs/`, 387 rules) + CEL evaluation |
| `pkg/hydra/` | Brute force: 11 protocol implementations and built-in credential lists |
| `pkg/discover/` | NIC and routing-table subnet discovery |
| `pkg/pool/` | Worker pool used by the scan phases |
| `pkg/grdp/`, `pkg/gotelnet/` | RDP and Telnet protocol implementations |
| `pkg/simplehttp/`, `pkg/uri/`, `pkg/slog/`, `pkg/misc/` | HTTP helpers, target parsing, logging, utilities |

## License

Copyright (C) 2026 ZackSecurity

This project is licensed under the **GNU General Public License v3.0 or later**
(GPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.
