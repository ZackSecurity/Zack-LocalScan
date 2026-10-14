// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package redis

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Timeout is the connection timeout for Redis. Hardcoded 2s — single AUTH command, fastest protocol.
var Timeout = 2 * time.Second

func Check(Host, Password string, Port int) error {
	netloc := Host + ":" + fmt.Sprint(Port)
	conn, err := net.DialTimeout("tcp", netloc, Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(Timeout))
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", Password)))
	if err != nil {
		return err
	}
	reply, err := readResponse(conn)
	if err != nil {
		return err
	}
	if strings.Contains(reply, "+OK") == false {
		return errors.New("login failed")
	}
	return nil
}

func readResponse(conn net.Conn) (r string, err error) {
	buf := make([]byte, 4096)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		r += string(buf[0:count])
		if count < 4096 {
			break
		}
	}
	return r, err
}
