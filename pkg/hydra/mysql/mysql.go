// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package mysql

import (
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"log"
	"time"
)

// Timeout is the connection timeout for MySQL. Hardcoded 4s — TCP+handshake+auth, moderate complexity.
var Timeout = 4 * time.Second

func Check(Host, Username, Password string, Port int) error {
	_ = mysql.SetLogger(log.New(io.Discard, "", log.Ldate|log.Ltime))
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/information_schema?charset=utf8&timeout=%v", Username, Password, Host, Port, Timeout)
	db, err := sql.Open("mysql", dataSourceName)
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
