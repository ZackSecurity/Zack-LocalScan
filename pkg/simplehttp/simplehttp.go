// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package simplehttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	readTimeout   = "read response timeout"
	readBodyError = "read response body error"
)

var (
	errorsReadTimeout   = errors.New(readTimeout)
	errorsReadBodyError = errors.New(readBodyError)
)

type Response struct {
	*http.Response
	Raw *Raw
}

type Raw struct {
	Header string
	Body   string
	Cert   string
}

func (r *Raw) String() string {
	return r.Header + "\r\n" + r.Body
}

// NewClientWithTimeout creates an HTTP client where every sub-timeout
// (TCP dial, TLS handshake, overall request) is controlled by timeout.
func NewClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   timeout,
			IdleConnTimeout:       10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
			DisableKeepAlives: true,
		},
	}
}

func Do(c *http.Client, req *http.Request) (*Response, error) {
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}

	response, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { response.Body.Close() }()
	resp := NewResponse(response)
	resp.Raw.Header = GetHeaderRaw(response)
	resp.Raw.Cert = GetCertRaw(response.TLS)
	bodyBuf, err := ReadBodyTimeout(response.Body, time.Second*2)
	if err != nil {
		return resp, errorsReadBodyError
	}
	resp.Raw.Body = string(bodyBuf)
	return resp, nil
}

func NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	return req, nil
}

func NewResponse(response *http.Response) *Response {
	return &Response{
		Response: response,
		Raw: &Raw{
			Header: "",
			Body:   "",
		},
	}
}

func RandomUserAgent() string {
	// Go 1.20+ auto-seeds the global source and rand.Intn is thread-safe.
	i := rand.Intn(len(userAgents))
	return userAgents[i] + " Time/" + strconv.FormatInt(time.Now().UnixMilli(), 10)
}

func ReadBodyTimeout(reader io.Reader, duration time.Duration) ([]byte, error) {
	type readResult struct {
		buf []byte
		err error
	}
	// Buffered channel: after a timeout return the reader goroutine can still finish and
	// send without blocking; the old named-return version had a data race with the caller.
	ch := make(chan readResult, 1)
	go func() {
		buf, err := io.ReadAll(reader)
		ch <- readResult{buf, err}
	}()

	select {
	case r := <-ch:
		return r.buf, r.err
	case <-time.After(duration):
		return nil, errorsReadTimeout
	}
}

func GetHeaderRaw(response *http.Response) string {
	headerString := fmt.Sprintf("%s %s\r\n", response.Proto, response.Status)
	for key, value := range response.Header {
		headerString += fmt.Sprintf("%s: %s\r\n", key, strings.Join(value, ";"))
	}
	return headerString
}

func GetCertRaw(TLS *tls.ConnectionState) string {
	if TLS == nil {
		return ""
	}
	if len(TLS.PeerCertificates) == 0 {
		return ""
	}
	var raw string
	cert := TLS.PeerCertificates[0]
	raw += fmt.Sprint(toRaw(cert))
	raw += "\r\n"
	raw += "SUBJECT:\r\n"
	raw += fmt.Sprint(toRaw(cert.Subject))
	raw += "\r\n"
	raw += "Issuer:\r\n"
	raw += fmt.Sprint(toRaw(cert.Issuer))
	return raw
}

func SplitHeaderAndBody(response string) (header, body string) {
	index := strings.Index(response, "\r\n\r\n")
	if index == -1 {
		header = response
	} else {
		header = response[:index]
		body = response[index:]
	}
	return header, body
}

type stringer interface {
	String() string
}

func toRaw(value interface{}) string {
	t := reflect.TypeOf(value)
	v := reflect.ValueOf(value)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		v = v.Elem()
	}
	var raw string
	for i := 0; i < t.NumField(); i++ {
		// iterate over the struct fields
		key := t.Field(i)
		// read the field value through the interface
		value := v.Field(i).Interface()
		var cell string
		switch s := value.(type) {
		case string:
			cell = s
		case []string:
			cell = strings.Join(s, "; ")
		case int:
			cell = strconv.Itoa(s)
		case stringer:
			cell = s.String()
		}
		if cell == "" {
			continue
		}
		raw += fmt.Sprintf("%s: %s\r\n", key.Name, cell)
	}
	return raw

}

// userAgents — representative modern browser UAs for fingerprint diversity.
// Kept to 20 entries to reduce binary bloat while covering major browsers/versions.
var userAgents = []string{
	// Chrome on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	// Chrome on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	// Firefox on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
	// Firefox on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	// Edge on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
	// Safari on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	// Safari on iOS
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	// Chrome on Android
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.66 Mobile Safari/537.36",
	// Chrome on Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Firefox on Linux
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	// Legacy IE for older Windows servers
	"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
	// curl / automation UA (bare-bones)
	"curl/8.4.0",
}
