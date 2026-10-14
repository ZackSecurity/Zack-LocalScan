// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

func DefaultTelnetList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"admin",
		"root",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("admin", "Admin@huawei"),
		NewSpecialAuth("root", "adminHW"),
		NewSpecialAuth("oracle", "oracle"),
		NewSpecialAuth("postgres", "postgres"),
	}
	return a
}
