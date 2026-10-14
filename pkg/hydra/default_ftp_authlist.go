// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

func DefaultFtpList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"anonymous",
		"admin",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("anonymous", "anonymous"),
		NewSpecialAuth("ftp", "ftp"),
	}
	return a
}
