// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package pocScan

import (
	"Zack-LocalScan/internal"
	"Zack-LocalScan/pkg/pocscan/lib"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func WebTitle(info *internal.HostInfo) error {
	err := GOWebTitle(info)
	WebScan(info)
	return err
}

func GOWebTitle(info *internal.HostInfo) (err error) {
	if ip := net.ParseIP(info.Host); ip != nil {
		if ip.To4() != nil {
			if info.Url == "" {
				switch info.Ports {
				case "80":
					info.Url = fmt.Sprintf("http://%s", info.Host)
				case "443":
					info.Url = fmt.Sprintf("https://%s", info.Host)
				default:
					host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
					protocol := GetProtocol(host, int64(internal.Args.Timeout))
					info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
				}
			} else {
				if !strings.Contains(info.Url, "://") {
					host := strings.Split(info.Url, "/")[0]
					protocol := GetProtocol(host, int64(internal.Args.Timeout))
					info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
				}
			}
		} else if ip.To16() != nil {
			if info.Url == "" {
				switch info.Ports {
				case "80":
					info.Url = fmt.Sprintf("http://[%s]", info.Host)
				case "443":
					info.Url = fmt.Sprintf("https://[%s]", info.Host)
				default:
					host := fmt.Sprintf("[%s]:%s", info.Host, info.Ports)
					protocol := GetProtocol(host, int64(internal.Args.Timeout))
					info.Url = fmt.Sprintf("%s://[%s]:%s", protocol, info.Host, info.Ports)
				}
			} else {
				if !strings.Contains(info.Url, "://") {
					host := strings.Split(info.Url, "/")[0]
					protocol := GetProtocol(host, int64(internal.Args.Timeout))
					info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
				}
			}
		}
	}
	err, result := geturl(info, 1)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}
	if result == "" && err != nil {
		return
	}

	if strings.Contains(result, "://") {
		info.Url = result
		err, result = geturl(info, 3)
		if err != nil {
			return
		}
	}

	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result = geturl(info, 1)
		if strings.Contains(result, "://") {
			info.Url = result
			err, _ = geturl(info, 3)
			if err != nil {
				return
			}
		}
	}
	if err != nil {
		return
	}
	return
}

func geturl(info *internal.HostInfo, flag int) (error, string) {
	//flag 1 first try
	//flag 3 302
	//flag 4 400 -> https

	Url := info.Url
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return err, "https"
	}
	req.Header.Set("User-agent", internal.UserAgent)
	req.Header.Set("Accept", internal.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Connection", "close")
	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect
	} else {
		client = lib.Client
	}

	resp, err := client.Do(req)
	if err != nil {
		return err, "https"
	}

	defer resp.Body.Close()

	var reurl string
	redirURL, err1 := resp.Location()
	if err1 == nil {
		reurl = redirURL.String()
	}
	if reurl != "" {
		return nil, reurl
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		return nil, "https"
	}
	return nil, ""
}

func GetProtocol(host string, Timeout int64) (protocol string) {
	protocol = "http"
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}

	tcpConn, err := net.DialTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}
	conn := tls.Client(tcpConn, &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
