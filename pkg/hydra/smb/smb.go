// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package smb

import (
	"context"
	"errors"
	"github.com/stacktitan/smb/smb"
	"time"
)

// Timeout is the connection timeout for SMB. Hardcoded 6s — NTLMSSP multi-round (negotiate→challenge→auth), slowest common protocol.
var Timeout = 6 * time.Second

var (
	LoginFailedError  = errors.New("login failed")
	LoginTimeoutError = errors.New("login timeout")
)

func Check(Host, Username, Domain, Password string, Port int) error {
	status := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	options := smb.Options{
		Host:        Host,
		Port:        Port,
		User:        Username,
		Password:    Password,
		Domain:      Domain,
		Workstation: "",
	}
	// perform the SMB connection
	go func() {
		session, err := smb.NewSession(options, false)
		if err != nil {
			status <- err
			return
		}
		defer session.Close()
		if session.IsAuthenticated == false {
			status <- LoginFailedError
			return
		}
		status <- nil
	}()

	select {
	case <-ctx.Done():
		return LoginTimeoutError
	case err := <-status:
		return err
	}

}
