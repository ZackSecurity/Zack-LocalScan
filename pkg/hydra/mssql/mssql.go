// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package mssql

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	mssql "github.com/denisenkom/go-mssqldb"
	"io"
	"log"
	"time"
)

// Timeout is the connection timeout for MSSQL. Hardcoded 5s — TDS protocol + NTLM authentication overhead.
var Timeout = 5 * time.Second

func Check(Host, Username, Password string, Port int) error {
	mssql.SetLogger(log.New(io.Discard, "", log.Ldate|log.Ltime))
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", Host, Username, Password, Port, Timeout)
	db, err := sql.Open("mssql", dataSourceName)
	if err != nil {
		return err
	}
	db.SetConnMaxLifetime(Timeout)
	db.SetMaxIdleConns(0)
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return err
	}
	return nil
}
