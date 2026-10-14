// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package ssh

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"time"
)

// Timeout is the connection timeout for SSH. Hardcoded 3s — TCP+SSH handshake+auth, fast enough on LAN.
var Timeout = 3 * time.Second

func Check(Host, Username, Password string, Port int) error {
	var Auth = []ssh.AuthMethod{ssh.Password(Password)}
	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: Timeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", Host, Port), config)
	if err != nil {
		return err
	}
	defer client.Close()
	return nil
}
