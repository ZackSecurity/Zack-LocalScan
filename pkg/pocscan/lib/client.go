// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package lib

import (
	"Zack-LocalScan/internal"
	"Zack-LocalScan/pkg/slog"
	"crypto/tls"
	"embed"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
	keepAlive        = 5 * time.Second
)

func Inithttp() {
	if internal.Setting.PocNum == 0 {
		internal.Setting.PocNum = 20
	}
	InitHttpClient(internal.Setting.PocNum, time.Duration(internal.Setting.WebTimeout)*time.Second)
}

func InitHttpClient(ThreadsNum int, Timeout time.Duration) {
	dialer := &net.Dialer{
		Timeout:   Timeout,
		KeepAlive: keepAlive,
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
		TLSHandshakeTimeout: Timeout,
		DisableKeepAlives:   false,
	}

	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type Poc struct {
	Name   string  `yaml:"name"`
	Set    StrMap  `yaml:"set"`
	Sets   ListMap `yaml:"sets"`
	Rules  []Rules `yaml:"rules"`
	Groups RuleMap `yaml:"groups"`
	Detail Detail  `yaml:"detail"`
}

type MapSlice = yaml.MapSlice

type StrMap []StrItem
type ListMap []ListItem
type RuleMap []RuleItem

type StrItem struct {
	Key, Value string
}

type ListItem struct {
	Key   string
	Value []string
}

type RuleItem struct {
	Key   string
	Value []Rules
}

func (r *StrMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	for _, one := range tmp {
		key, ok := one.Key.(string)
		if !ok {
			continue
		}
		value, ok := one.Value.(string)
		if !ok {
			value = fmt.Sprintf("%v", one.Value)
		}
		*r = append(*r, StrItem{key, value})
	}
	return nil
}

func (r *RuleMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp1 yaml.MapSlice
	if err := unmarshal(&tmp1); err != nil {
		return err
	}
	var tmp = make(map[string][]Rules)
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	for _, one := range tmp1 {
		key := one.Key.(string)
		value := tmp[key]
		*r = append(*r, RuleItem{key, value})
	}
	return nil
}

func (r *ListMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	for _, one := range tmp {
		key, ok := one.Key.(string)
		if !ok {
			continue
		}
		var value []string
		valSlice, ok := one.Value.([]interface{})
		if !ok {
			continue
		}
		for _, val := range valSlice {
			v := fmt.Sprintf("%v", val)
			value = append(value, v)
		}
		*r = append(*r, ListItem{key, value})
	}
	return nil
}

type Rules struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
	Continue        bool              `yaml:"continue"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

func LoadPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)

	if err != nil {
		slog.Printf(slog.DEBUG, "load poc %s error1: %v", fileName, err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		slog.Printf(slog.DEBUG, "load poc %s error2: %v", fileName, err)
		return nil, err
	}
	// Rewrite header keys in expressions to Go's canonical MIME form (net/http stores
	// header names the same way), or spellings like "location"/"set-Cookie" never match.
	for i := range p.Rules {
		p.Rules[i].Expression = normalizeHeaderKeys(p.Rules[i].Expression)
	}
	for i := range p.Groups {
		for j := range p.Groups[i].Value {
			p.Groups[i].Value[j].Expression = normalizeHeaderKeys(p.Groups[i].Value[j].Expression)
		}
	}
	return p, err
}

// Matches header key literals in response.headers["Key"] / response.headers['Key'].
var headerIndexRe = regexp.MustCompile(`(\.headers\s*\[\s*)(["'])([^"']+)(["'])`)

// Matches "Key" in response.headers; the trailing char must not be "[" so that substring
// checks like "sub" in response.headers["X"] are left untouched.
var headerInRe = regexp.MustCompile(`(["'])([^"']+)(["'])(\s+in\s+[A-Za-z0-9_.]*\.headers)([^[]|$)`)

// normalizeHeaderKeys rewrites response-header key literals inside CEL expressions
// into textproto.CanonicalMIMEHeaderKey form; non-literals (vars, concatenation) stay.
func normalizeHeaderKeys(expr string) string {
	if !strings.Contains(expr, "headers") {
		return expr
	}
	expr = headerIndexRe.ReplaceAllStringFunc(expr, func(m string) string {
		parts := headerIndexRe.FindStringSubmatch(m)
		return parts[1] + parts[2] + textproto.CanonicalMIMEHeaderKey(parts[3]) + parts[4]
	})
	expr = headerInRe.ReplaceAllStringFunc(expr, func(m string) string {
		parts := headerInRe.FindStringSubmatch(m)
		return parts[1] + textproto.CanonicalMIMEHeaderKey(parts[2]) + parts[3] + parts[4] + parts[5]
	})
	return expr
}
