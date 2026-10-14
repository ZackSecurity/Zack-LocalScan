// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

func DefaultMssqlList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"sa",
		"sql",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{}
	return a
}
