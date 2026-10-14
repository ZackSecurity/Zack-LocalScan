// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package rdp

import (
	"Zack-LocalScan/pkg/grdp"
	"fmt"
)

func Check(ip, domain, login, password string, port int, protocol string) error {
	var err error
	target := fmt.Sprintf("%s:%d", ip, port)
	if protocol == grdp.PROTOCOL_SSL {
		err = grdp.LoginForSSL(target, domain, login, password)
	} else {
		err = grdp.LoginForRDP(target, domain, login, password)
	}
	if err != nil {
		return err
	}
	return nil
}
