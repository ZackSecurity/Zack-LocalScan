// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package telnet

import (
	"Zack-LocalScan/pkg/gotelnet"
)

func Check(addr, username, password string, port, serverType int) error {
	client := gotelnet.New(addr, port)
	err := client.Connect()
	if err != nil {
		return err
	}
	defer client.Close()
	client.UserName = username
	client.Password = password
	client.ServerType = serverType
	err = client.Login()
	if err != nil {
		return err
	}
	return nil
}
