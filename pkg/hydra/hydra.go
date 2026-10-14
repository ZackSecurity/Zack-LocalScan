// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

import (
	"Zack-LocalScan/pkg/hydra/oracle"
	"Zack-LocalScan/pkg/gotelnet"
	"Zack-LocalScan/pkg/pool"
	"Zack-LocalScan/pkg/slog"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
)

type Cracker struct {
	Pool     *pool.Pool
	authList *AuthList
	authInfo *AuthInfo

	retries  int
	attempts int32

	SuccessCount int32
	SuccessAuth  Auth
	successMu    sync.Mutex
}

func init() {
	InitDefaultAuthMap()
}

func InitDefaultAuthMap() {
	m := make(map[string]*AuthList)
	m["rdp"] = DefaultRdpList()
	m["ssh"] = DefaultSshList()
	m["mysql"] = DefaultMysqlList()
	m["mssql"] = DefaultMssqlList()
	m["oracle"] = DefaultOracleList()
	m["postgresql"] = DefaultPostgresqlList()
	m["redis"] = DefaultRedisList()
	m["ftp"] = DefaultFtpList()
	m["mongodb"] = DefaultMongodbList()
	m["smb"] = DefaultSmbList()
	m["telnet"] = DefaultTelnetList()
	DefaultAuthMap = m
}

type loginType string

const (
	ProtocolInvalid                 loginType = "ProtocolInvalid"
	UsernameAndPassword                       = "UsernameAndPassword"
	OnlyPassword                              = "OnlyPassword"
	UnauthorizedAccessVulnerability           = "UnauthorizedAccessVulnerability"
)

var (
	DefaultAuthMap map[string]*AuthList
	LoginFailedErr = errors.New("login failed")
	ProtocolErr    = errors.New("protocol error")
)

func NewCracker(info *AuthInfo, threads int) *Cracker {
	c := &Cracker{}
	c.retries = 1
	c.Pool = pool.New(threads)
	c.authInfo = info
	c.authList = DefaultAuthMap[c.authInfo.Protocol]
	if c.authList == nil {
		c.authList = NewAuthList()
	}
	c.Pool.Interval = 0
	return c
}

func (c *Cracker) Retries(i int) {
	if i <= 0 {
		return
	}
	c.retries = i
}

func (c *Cracker) success(info Auth) {
	c.successMu.Lock()
	if atomic.LoadInt32(&c.SuccessCount) == 0 {
		c.SuccessAuth = info
	}
	c.successMu.Unlock()
	atomic.AddInt32(&c.SuccessCount, 1)
}

func (c *Cracker) Run() (*Auth, error) {
	switch c.initJobFunc() {
	case ProtocolInvalid:
		return nil, ProtocolErr
	case UsernameAndPassword:
		go c.dispatcher(false)
	case OnlyPassword:
		go c.dispatcher(true)
	case UnauthorizedAccessVulnerability:
		return &UnauthorizedAccessVulnerabilityAuth, nil
	}
	// start brute forcing
	c.Pool.Run()
	switch {
	case c.SuccessCount == 0:
		return nil, LoginFailedErr
	case c.SuccessCount <= 3:
		return &c.SuccessAuth, nil
	default:
		return nil, ProtocolErr
	}
}

func (c *Cracker) initJobFunc() loginType {
	ip := c.authInfo.IPAddr
	port := c.authInfo.Port
	// select the per-protocol cracking function
	switch c.authInfo.Protocol {
	case "rdp":
		c.Pool.Function = c.generateWorker(rdpCracker(ip, port))
	case "mysql":
		c.Pool.Function = c.generateWorker(mysqlCracker)
	case "mssql":
		c.Pool.Function = c.generateWorker(mssqlCracker)
	case "oracle":
		// unknown SID: skip brute forcing for this target
		sid := oracle.GetSID(ip, port, oracle.ServiceName)
		if sid == "" {
			return ProtocolInvalid
		}
		c.Pool.Function = c.generateWorker(oracleCracker(sid))
	case "postgresql":
		c.Pool.Function = c.generateWorker(postgresqlCracker)
	case "ssh":
		c.Pool.Function = c.generateWorker(sshCracker)
	case "telnet":
		serverType := getTelnetServerType(ip, port)
		if serverType == gotelnet.UnauthorizedAccess {
			return UnauthorizedAccessVulnerability
		}
		if serverType == gotelnet.Closed {
			return ProtocolInvalid
		}
		c.Pool.Function = c.generateWorker(telnetCracker(serverType))
		if serverType == gotelnet.OnlyPassword {
			return OnlyPassword
		}
	case "ftp":
		c.Pool.Function = c.generateWorker(ftpCracker)
	case "mongodb":
		c.Pool.Function = c.generateWorker(mongodbCracker)
	case "redis":
		c.Pool.Function = c.generateWorker(redisCracker)
		return OnlyPassword
	case "smb":
		c.Pool.Function = c.generateWorker(smbCracker)
	default:
		return ProtocolInvalid
	}
	return UsernameAndPassword
}

func (c *Cracker) generateWorker(f func(interface{}) error) func(interface{}) {
	return func(in interface{}) {
		for j := 0; j < c.retries; j++ {
			info := in.(AuthInfo)
			info.Auth.MakePassword()
			err := f(info)
			if err == nil {
				info.Status = true
				c.success(info.Auth)
				break
			}
			if strings.Contains(err.Error(), "timeout") == true {
				continue
			}
			if strings.Contains(err.Error(), "EOF") == true {
				continue
			}
			break
		}
		n := atomic.AddInt32(&c.attempts, 1)
		if n%30 == 0 {
			slog.Printf(slog.DEBUG, "  hydra %s:%d %d attempts...", c.authInfo.IPAddr, c.authInfo.Port, n)
		}
	}
}

// dispatcher
func (c *Cracker) dispatcher(onlyPassword bool) {
	for _, auth := range c.authList.Dict(onlyPassword) {
		if atomic.LoadInt32(&c.SuccessCount) > 0 {
			break
		}
		info := *c.authInfo
		info.Auth = auth
		c.Pool.Push(info)
	}
	// close the channel
	c.Pool.Stop()
}
