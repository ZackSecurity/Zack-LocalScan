// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

func DefaultRedisList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"",
	}
	a.Password = []string{
		"redis",
		"123456",
		"password",
		"12345",
		"1234",
		"123",
		"0000",
		"12345678",
		"1q2w3e",
		"abc123",
	}
	a.Special = []Auth{}
	return a
}
