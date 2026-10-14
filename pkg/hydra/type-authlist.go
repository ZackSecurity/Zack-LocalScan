// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package hydra

type AuthList struct {
	Username []string
	Password []string
	Special  []Auth
}

func NewAuthList() *AuthList {
	a := &AuthList{}
	a.Special = []Auth{}
	return a
}

func (a *AuthList) Dict(onlyPassword bool) []Auth {
	var dict []Auth
	if onlyPassword {
		dict = append(dict, NewAuthFromPasswords(a.Password)...)
	} else {
		dict = append(dict, a.Special...)
		dict = append(dict, NewAuthFromUsernameAndPassword(a.Username, a.Password)...)
	}
	return dict
}
