// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package grdp

import (
	"Zack-LocalScan/pkg/grdp/glog"
	"fmt"
	"testing"
)

func testrdp(target string) {
	domain := ""
	username := "administrator"
	password := "zaq1@WSX"
	//target = "180.102.17.30:3389"
	var err error
	g := NewClient(target, glog.NONE)
	// SSL login test
	err = g.loginForSSL(domain, username, password)
	if err == nil {
		fmt.Println("Login Success")
		return
	}
	if err.Error() != "PROTOCOL_RDP" {
		fmt.Println("Login Error:", err)
		return
	}
	// RDP login test
	err = g.loginForRDP(domain, username, password)
	if err == nil {
		fmt.Println("Login Success")
		return
	} else {
		fmt.Println("Login Error:", err)
		return
	}
}

func TestName(t *testing.T) {
	targetArr := []string{
		//"50.57.49.172:3389",
		//"20.49.22.250:3389",
		"192.168.217.166:3389",
	}
	for _, target := range targetArr {
		fmt.Println(target)
		testrdp(target)
	}
}
