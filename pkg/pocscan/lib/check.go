// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package lib

import (
	"Zack-LocalScan/internal"
	"Zack-LocalScan/pkg/slog"
	"crypto/md5"
	"fmt"
	"github.com/google/cel-go/cel"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

type Task struct {
	Req *http.Request
	Poc *Poc
}

func CheckMultiPoc(req *http.Request, pocs []*Poc, workers int) {
	tasks := make(chan Task)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		go func() {
			for task := range tasks {
				isVul, _, name := executePoc(task.Req, task.Poc)
				if isVul {
					pocLabel := task.Poc.Name
					if name != "" {
						pocLabel += "," + name
					}
					slog.Println(slog.DATA, fmt.Sprintf("  %-30v %s", task.Req.URL, pocLabel))
					internal.PocResultsMu.Lock()
					internal.PocResults = append(internal.PocResults, fmt.Sprintf("  %-30s %s", task.Req.URL.String(), pocLabel))
					internal.PocResultsMu.Unlock()
				}
				wg.Done()
			}
		}()
	}
	for _, poc := range pocs {
		task := Task{
			Req: req,
			Poc: poc,
		}
		wg.Add(1)
		tasks <- task
	}
	wg.Wait()
	close(tasks)
}

// getPocEnv returns the PoC's CEL environment, cached per PoC: the environment only
// depends on the PoC's own set/sets declarations, so rebuilding it per target wastes time.
var (
	pocEnvMu sync.Mutex
	pocEnvs  = make(map[*Poc]*cel.Env)
)

func getPocEnv(p *Poc) (*cel.Env, error) {
	pocEnvMu.Lock()
	defer pocEnvMu.Unlock()
	if env, ok := pocEnvs[p]; ok {
		return env, nil
	}
	c := NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	if len(p.Sets) > 0 {
		var setMap StrMap
		for _, item := range p.Sets {
			if len(item.Value) > 0 {
				setMap = append(setMap, StrItem{item.Key, item.Value[0]})
			} else {
				setMap = append(setMap, StrItem{item.Key, ""})
			}
		}
		c.UpdateCompileOptions(setMap)
	}
	env, err := NewEnv(&c)
	if err != nil {
		return nil, err
	}
	pocEnvs[p] = env
	return env, nil
}

func executePoc(oReq *http.Request, p *Poc) (bool, error, string) {
	env, err := getPocEnv(p)
	if err != nil {
		slog.Println(slog.DEBUG, "[-]", p.Name, "environment creation error:", err)
		return false, err, ""
	}
	req, err := ParseRequest(oReq)
	if err != nil {
		slog.Println(slog.DEBUG, "[-]", p.Name, "ParseRequest error:", err)
		return false, err, ""
	}
	variableMap := make(map[string]interface{})
	defer func() { variableMap = nil }()
	variableMap["request"] = req
	for _, item := range p.Set {
		k, expression := item.Key, item.Value
		if expression == "newReverse()" {
			// With DnsLog off or the OOB self-test failed, newReverse() returns an empty Reverse:
			// only reverse-dependent rules fail; the PoC's other rules/groups still run.
			variableMap[k] = newReverse()
			continue
		}
		err, _ = evalset(env, variableMap, k, expression)
		if err != nil {
			slog.Println(slog.DEBUG, "[-]", p.Name, "evalset error:", err, "k:", k, "expression:", expression)
		}
	}
	success := false
	// fuzzing mode, e.g. Tomcat weak credentials
	if len(p.Sets) > 0 {
		success, err = clusterpoc(oReq, p, variableMap, req, env)
		return success, nil, ""
	}

	DealWithRule := func(rule Rules) (bool, error) {
		Headers := cloneMap(rule.Headers)
		var (
			flag, ok bool
		)
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range Headers {
				if !strings.Contains(v2, "{{"+k1+"}}") {
					continue
				}
				Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(rule.Path, "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(rule.Body, "{{"+k1+"}}", value)
		}
		rule.Headers = Headers

		resp, err := sendRule(oReq, req, rule)
		if err != nil {
			return false, err
		}
		variableMap["response"] = resp
		// first check whether the response matches the search rule
		if !applySearch(resp, rule, variableMap) {
			return false, nil
		}
		out, err := Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			return false, err
		}
		// false stops the rule chain
		// if the last step fails, the whole chain counts as failed
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}
		return flag, nil
	}

	DealWithRules := func(rules []Rules) bool {
		successFlag := false
		for _, rule := range rules {
			flag, err := DealWithRule(rule)
			if err != nil || !flag { // false stops the rule chain
				successFlag = false // one failed step breaks the chain
				break
			}
			successFlag = true
		}
		return successFlag
	}

	if len(p.Rules) > 0 {
		success = DealWithRules(p.Rules)
	} else {
		for _, item := range p.Groups {
			name, rules := item.Key, item.Value
			success = DealWithRules(rules)
			if success {
				return success, nil, name
			}
		}
	}

	return success, nil, ""
}

var (
	regexCache = make(map[string]*regexp.Regexp)
	regexMu    sync.RWMutex
)

func getRegexp(pattern string) *regexp.Regexp {
	regexMu.RLock()
	re, ok := regexCache[pattern]
	regexMu.RUnlock()
	if ok {
		return re
	}
	regexMu.Lock()
	defer regexMu.Unlock()
	re, ok = regexCache[pattern]
	if ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		slog.Println(slog.DEBUG, "regexp.Compile error:", err)
		return nil
	}
	regexCache[pattern] = re
	return re
}

func doSearch(re string, body string) map[string]string {
	r := getRegexp(re)
	if r == nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				if strings.HasPrefix(re, "Set-Cookie:") && strings.Contains(name, "cookie") {
					paramsMap[name] = optimizeCookies(result[i])
				} else {
					paramsMap[name] = result[i]
				}
			}
		}
		return paramsMap
	}
	return nil
}

func optimizeCookies(rawCookie string) (output string) {
	// Parse the cookies
	parsedCookie := strings.Split(rawCookie, "; ")
	for _, c := range parsedCookie {
		nameVal := strings.Split(c, "=")
		if len(nameVal) >= 2 {
			switch strings.ToLower(nameVal[0]) {
			case "expires", "max-age", "path", "domain", "version", "comment", "secure", "samesite", "httponly":
				continue
			}
			output += fmt.Sprintf("%s=%s; ", nameVal[0], strings.Join(nameVal[1:], "="))
		}
	}

	return
}

func newReverse() *Reverse {
	// With DnsLog off or the OOB self-test failed, return an empty Reverse: reverse rules
	// fail naturally without aborting the PoC; local detection rules still run.
	if !internal.Setting.DnsLog || !oobReady.Load() {
		return &Reverse{}
	}
	_, host, _ := newCallback()
	if host == "" {
		return &Reverse{}
	}
	urlStr := "http://" + host
	u, _ := url.Parse(urlStr)
	return &Reverse{
		Url:                urlStr,
		Domain:             u.Hostname(),
		Ip:                 u.Host,
		IsDomainNameServer: false,
	}
}

func clusterpoc(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env) (success bool, err error) {
	var strMap StrMap
	var tmpnum int
	for i, rule := range p.Rules {
		if !isFuzz(rule, p.Sets) {
			success, err = clustersend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success {
				continue
			} else {
				return false, err
			}
		}
		setsMap := Combo(p.Sets)
		ruleHash := make(map[string]struct{})
	look:
		for j, item := range setsMap {
			// by default only 10 Shiro keys are tried
			if p.Name == "poc-yaml-shiro-key" && !internal.Setting.PocFull && j >= 10 {
				if item[1] == "cbc" {
					continue
				} else {
					if tmpnum == 0 {
						tmpnum = j
					}
					if j-tmpnum >= 10 {
						break
					}
				}
			}
			rule1 := cloneRules(rule)
			var flag1 bool
			var tmpMap StrMap
			var payloads = make(map[string]interface{})
			var tmpexpression string
			for i, one := range p.Sets {
				key, expression := one.Key, item[i]
				if key == "payload" {
					tmpexpression = expression
				}
				_, output := evalset1(env, variableMap, key, expression)
				payloads[key] = output
			}
			for _, one := range p.Sets {
				flag := false
				key := one.Key
				value := fmt.Sprintf("%v", payloads[key])
				for k2, v2 := range rule1.Headers {
					if strings.Contains(v2, "{{"+key+"}}") {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+key+"}}", value)
						flag = true
					}
				}
				if strings.Contains(rule1.Path, "{{"+key+"}}") {
					rule1.Path = strings.ReplaceAll(rule1.Path, "{{"+key+"}}", value)
					flag = true
				}
				if strings.Contains(rule1.Body, "{{"+key+"}}") {
					rule1.Body = strings.ReplaceAll(rule1.Body, "{{"+key+"}}", value)
					flag = true
				}
				if flag {
					flag1 = true
					if key == "payload" {
						var flag2 bool
						for k, v := range variableMap {
							if strings.Contains(tmpexpression, k) {
								flag2 = true
								tmpMap = append(tmpMap, StrItem{k, fmt.Sprintf("%v", v)})
							}
						}
						if flag2 {
							continue
						}
					}
					tmpMap = append(tmpMap, StrItem{key, value})
				}
			}
			if !flag1 {
				continue
			}
			has := md5.Sum([]byte(fmt.Sprintf("%v", rule1)))
			md5str := fmt.Sprintf("%x", has)
			if _, ok := ruleHash[md5str]; ok {
				continue
			}
			ruleHash[md5str] = struct{}{}
			success, err = clustersend(oReq, variableMap, req, env, rule1)
			if err != nil {
				return false, err
			}
			if success {
				if rule.Continue {
					if p.Name == "poc-yaml-backup-file" || p.Name == "poc-yaml-sql-file" {
						slog.Println(slog.DATA, fmt.Sprintf("  %-30v %s", fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), p.Name))
						internal.PocResultsMu.Lock()
						internal.PocResults = append(internal.PocResults, fmt.Sprintf("  %-30s %s", fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), p.Name))
						internal.PocResultsMu.Unlock()
					} else {
						pocLabel := req.Url.Host + "," + req.Url.Path + "," + p.Name
						slog.Println(slog.DATA, fmt.Sprintf("  %-30v %s %v", fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), pocLabel, tmpMap))
						internal.PocResultsMu.Lock()
						internal.PocResults = append(internal.PocResults, fmt.Sprintf("  %-30s %s", fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), p.Name))
						internal.PocResultsMu.Unlock()
					}
					continue
				}
				strMap = append(strMap, tmpMap...)
				if i == len(p.Rules)-1 {
					pocLabel := req.Url.Host + "," + req.Url.Path + "," + p.Name
					slog.Println(slog.DATA, fmt.Sprintf("  %-30v %s %v", fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), pocLabel, tmpMap))
					internal.PocResultsMu.Lock()
					internal.PocResults = append(internal.PocResults, fmt.Sprintf("  %-30s %s", fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), p.Name))
					internal.PocResultsMu.Unlock()
					// stop printing further PoC success messages
					return false, nil
				}
				break look
			}
		}
		if !success {
			break
		}
		if rule.Continue {
			// stop printing further PoC success messages
			return false, nil
		}
	}
	return success, nil
}

func isFuzz(rule Rules, Sets ListMap) bool {
	for _, one := range Sets {
		key := one.Key
		for _, v := range rule.Headers {
			if strings.Contains(v, "{{"+key+"}}") {
				return true
			}
		}
		if strings.Contains(rule.Path, "{{"+key+"}}") {
			return true
		}
		if strings.Contains(rule.Body, "{{"+key+"}}") {
			return true
		}
	}
	return false
}

func Combo(input ListMap) (output [][]string) {
	if len(input) > 1 {
		output = Combo(input[1:])
		output = MakeData(output, input[0].Value)
	} else {
		for _, i := range input[0].Value {
			output = append(output, []string{i})
		}
	}
	return
}

func MakeData(base [][]string, nextData []string) (output [][]string) {
	for i := range base {
		for _, j := range nextData {
			tmp := make([]string, 0, len(base[i])+1)
			tmp = append(tmp, j)
			tmp = append(tmp, base[i]...)
			output = append(output, tmp)
		}
	}
	return
}

func clustersend(oReq *http.Request, variableMap map[string]interface{}, req *Request, env *cel.Env, rule Rules) (bool, error) {
	// The rule comes from the process-wide AllPocs; its Headers map is shared by all
	// concurrent workers: deep-copy before substituting, or map writes crash and stale values bake in.
	rule = cloneRules(rule)
	for k1, v1 := range variableMap {
		_, isMap := v1.(map[string]string)
		if isMap {
			continue
		}
		value := fmt.Sprintf("%v", v1)
		for k2, v2 := range rule.Headers {
			if strings.Contains(v2, "{{"+k1+"}}") {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
		}
		rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
		rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
	}
	resp, err := sendRule(oReq, req, rule)
	if err != nil {
		return false, err
	}
	variableMap["response"] = resp
	// first check whether the response matches the search rule
	if !applySearch(resp, rule, variableMap) {
		return false, nil
	}
	out, err := Evaluate(env, rule.Expression, variableMap)
	if err != nil {
		if strings.Contains(err.Error(), "Syntax error") {
			slog.Println(slog.DEBUG, rule.Expression, err)
		}
		return false, err
	}
	if fmt.Sprintf("%v", out) == "false" { // false stops the rule chain
		return false, err // if the last step fails, the whole chain counts as failed
	}
	return true, err
}

func cloneRules(tags Rules) Rules {
	cloneTags := Rules{}
	cloneTags.Method = tags.Method
	cloneTags.Path = tags.Path
	cloneTags.Body = tags.Body
	cloneTags.Search = tags.Search
	cloneTags.FollowRedirects = tags.FollowRedirects
	cloneTags.Expression = tags.Expression
	cloneTags.Headers = cloneMap(tags.Headers)
	return cloneTags
}

func cloneMap(tags map[string]string) map[string]string {
	cloneTags := make(map[string]string)
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

// sendRule applies a fully-substituted rule to a request and sends it: path join, space
// escaping, header merge. Shared by DealWithRule and clustersend so they cannot drift.
func sendRule(oReq *http.Request, base *Request, rule Rules) (*Response, error) {
	if oReq.URL.Path != "" && oReq.URL.Path != "/" {
		base.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		base.Url.Path = rule.Path
	}
	// some PoCs do not separate path and query; handle it here
	base.Url.Path = strings.ReplaceAll(base.Url.Path, " ", "%20")
	newRequest, err := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", base.Url.Scheme, base.Url.Host, base.Url.Path), strings.NewReader(rule.Body))
	if err != nil {
		return nil, err
	}
	newRequest.Header = oReq.Header.Clone()
	for k, v := range rule.Headers {
		newRequest.Header.Set(k, v)
	}
	return DoRequest(newRequest, rule.FollowRedirects)
}

// applySearch matches the rule's search regex against headers+body and stores named
// capture groups into variableMap; false means no match and the chain must stop.
func applySearch(resp *Response, rule Rules, variableMap map[string]interface{}) bool {
	if rule.Search == "" {
		return true
	}
	result := doSearch(rule.Search, GetHeader(resp.Headers)+string(resp.Body))
	if len(result) == 0 { // regex did not match
		return false
	}
	for k, v := range result {
		variableMap[k] = v
	}
	return true
}

func evalset(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (err error, output string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		switch value := out.Value().(type) {
		case *UrlType:
			variableMap[k] = UrlTypeToString(value)
		case int64:
			variableMap[k] = int(value)
		default:
			variableMap[k] = fmt.Sprintf("%v", out)
		}
	}
	return err, fmt.Sprintf("%v", variableMap[k])
}

func evalset1(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (err error, output string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		variableMap[k] = fmt.Sprintf("%v", out)
	}
	return err, fmt.Sprintf("%v", variableMap[k])
}

func GetHeader(header map[string]string) (output string) {
	for name, values := range header {
		line := fmt.Sprintf("%s: %s\n", name, values)
		output = output + line
	}
	output = output + "\r\n"
	return
}
