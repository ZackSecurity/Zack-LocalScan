// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

type AuthInfo struct {
	Protocol string
	Port     int
	IPAddr   string
	Auth     Auth
	Status   bool
}

func NewAuthInfo(IPAddr string, Port int, Protocol string) *AuthInfo {
	a := &AuthInfo{
		Protocol: Protocol,
		Port:     Port,
		IPAddr:   IPAddr,
	}
	a.Auth = NewAuth()
	a.Status = false
	return a
}

