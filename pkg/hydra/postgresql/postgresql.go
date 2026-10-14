// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"time"
)

// Timeout is the connection timeout for PostgreSQL. Hardcoded 4s — TCP+SSL negotiation+auth.
var Timeout = 4 * time.Second

func Check(Host, Username, Password string, Port int) error {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v&connect_timeout=%v", Username, Password, Host, Port, "postgres", "disable", int(Timeout.Seconds()))
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return err
	}
	db.SetConnMaxLifetime(Timeout)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		return err
	}
	return nil
}
