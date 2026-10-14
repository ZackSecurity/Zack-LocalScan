// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package gotelnet

import (
	"fmt"
	"testing"
)

func TestTelnet(t *testing.T) {
	c := New("123.179.223.126", 23)
	err := c.Connect()
	if err != nil {
		return
	}

	//c.Close()
}

func TestByte(t *testing.T) {
	fmt.Printf("%v", Closed)
	fmt.Printf("%v", UnauthorizedAccess)
	fmt.Printf("%v", OnlyPassword)
	fmt.Printf("%v", UsernameAndPassword)
}
