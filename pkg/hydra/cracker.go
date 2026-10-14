// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

import (
	"Zack-LocalScan/pkg/hydra/ftp"
	"Zack-LocalScan/pkg/hydra/mongodb"
	"Zack-LocalScan/pkg/hydra/mssql"
	"Zack-LocalScan/pkg/hydra/mysql"
	"Zack-LocalScan/pkg/hydra/oracle"
	"Zack-LocalScan/pkg/hydra/postgresql"
	"Zack-LocalScan/pkg/hydra/rdp"
	"Zack-LocalScan/pkg/hydra/redis"
	"Zack-LocalScan/pkg/hydra/smb"
	"Zack-LocalScan/pkg/hydra/ssh"
	"Zack-LocalScan/pkg/hydra/telnet"
	"Zack-LocalScan/pkg/gotelnet"
	"Zack-LocalScan/pkg/grdp"
	"fmt"
)

func rdpCracker(IPAddr string, port int) func(interface{}) error {
	target := fmt.Sprintf("%s:%d", IPAddr, port)
	protocol := grdp.VerifyProtocol(target)
	//slog.Println(slog.DEBUG, "rdp protocol is :", protocol)
	return func(i interface{}) error {
		info := i.(AuthInfo)
		domain := ""
		return rdp.Check(info.IPAddr, domain, info.Auth.Username, info.Auth.Password, info.Port, protocol)
	}
}

func smbCracker(i interface{}) error {
	info := i.(AuthInfo)
	domain := ""
	return smb.Check(info.IPAddr, domain, info.Auth.Username, info.Auth.Password, info.Port)
}

func sshCracker(i interface{}) error {
	info := i.(AuthInfo)
	return ssh.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port)
}

func telnetCracker(serverType int) func(interface{}) error {
	return func(i interface{}) error {
		info := i.(AuthInfo)
		return telnet.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port, serverType)
	}
}

func getTelnetServerType(ip string, port int) int {
	client := gotelnet.New(ip, port)
	err := client.Connect()
	if err != nil {
		return gotelnet.Closed
	}
	defer client.Close()
	return client.MakeServerType()
}

func mysqlCracker(i interface{}) error {
	info := i.(AuthInfo)
	return mysql.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port)
}

func mssqlCracker(i interface{}) error {
	info := i.(AuthInfo)
	return mssql.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port)
}

func redisCracker(i interface{}) error {
	info := i.(AuthInfo)
	return redis.Check(info.IPAddr, info.Auth.Password, info.Port)
}

func ftpCracker(i interface{}) error {
	info := i.(AuthInfo)
	return ftp.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port)
}

func postgresqlCracker(i interface{}) error {
	info := i.(AuthInfo)
	return postgresql.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port)
}

func oracleCracker(sid string) func(interface{}) error {
	return func(i interface{}) error {
		info := i.(AuthInfo)
		// SID is passed as an argument; do not write the shared Auth.Other map - the
		// DefaultAuthMap entries are shared across targets and concurrent writes crash.
		return oracle.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port, sid)
	}
}

func mongodbCracker(i interface{}) error {
	info := i.(AuthInfo)
	return mongodb.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port)
}
