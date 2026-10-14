// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

func DefaultOracleList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"sys",
		"system",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("sys", "change_on_install"),
		NewSpecialAuth("system", "manager"),
		NewSpecialAuth("system", "oracle"),
		NewSpecialAuth("SCOTT", "TIGER"),
		NewSpecialAuth("DBSNMP", "DBSNMP"),
	}
	return a
}
