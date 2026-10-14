// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

func DefaultSshList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"root",
		"admin",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("oracle", "oracle"),
		NewSpecialAuth("mysql", "mysql"),
		NewSpecialAuth("postgres", "postgres"),
		NewSpecialAuth("kali", "kali"),
		NewSpecialAuth("admin", "Admin@huawei"),
		NewSpecialAuth("root", "adminHW"),
	}
	return a
}
