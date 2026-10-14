// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package ftp

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"time"
)

// Timeout is the connection timeout for FTP. Hardcoded 3s — simple TCP+banner+login handshake.
var Timeout = 3 * time.Second

func Check(Host, Username, Password string, Port int) error {
	conn, err := ftp.DialTimeout(fmt.Sprintf("%s:%d", Host, Port), Timeout)
	if err != nil {
		return err
	}
	defer conn.Logout()
	err = conn.Login(Username, Password)
	if err != nil {
		return err
	}
	return nil
}
