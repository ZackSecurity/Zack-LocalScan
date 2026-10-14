// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package pocScan

import (
	"Zack-LocalScan/internal"
	"Zack-LocalScan/pkg/pocscan/lib"
	"Zack-LocalScan/pkg/slog"
	"embed"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

//go:embed pocs
var Pocs embed.FS
var once sync.Once
var AllPocs []*lib.Poc

func WebScan(info *internal.HostInfo) {
	once.Do(initpoc)
	var pocinfo = internal.PocInfo{}
	URL, err := removeStandardPorts(info.Url)
	if err != nil {
		return
	}
	buf := strings.Split(URL, "/")
	pocinfo.Target = strings.Join(buf[:3], "/")

	// Run all PoCs against every HTTP target.
	Execute(pocinfo)
}

func Execute(PocInfo internal.PocInfo) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		//errlog := fmt.Sprintf("[-] webpocinit %v %v", PocInfo.Target, err)
		//common2.LogError(errlog)
		return
	}
	req.Header.Set("User-agent", internal.UserAgent)
	req.Header.Set("Accept", internal.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	lib.CheckMultiPoc(req, AllPocs, internal.Setting.PocNum)
}

func initpoc() {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		slog.Printf(slog.DEBUG, "init poc error: %v", err)
		return
	}
	for _, one := range entries {
		path := one.Name()
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			if poc, _ := lib.LoadPoc(path, Pocs); poc != nil {
				AllPocs = append(AllPocs, poc)
			}
		}
	}

}

func removeStandardPorts(rawURL string) (string, error) {
	// parse the URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// extract the port part
	host := u.Host
	colonIndex := strings.LastIndex(host, ":")
	if colonIndex != -1 {
		port := host[colonIndex+1:]
		if port == "80" || port == "443" {
			// strip the default port
			u.Host = host[:colonIndex]
		}
	}

	// rebuild the URL without the default port
	return u.String(), nil
}
