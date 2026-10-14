// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

func DefaultSmbList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"administrator",
		"admin",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("guest", "guest"),
	}
	return a
}
