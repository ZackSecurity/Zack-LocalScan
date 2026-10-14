// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package slog

import (
	"Zack-LocalScan/pkg/stdio"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
)

type Level int

const (
	DEBUG Level = 0x0000a1
	INFO        = 0x0000b2
	WARN        = 0x0000c3
	ERROR       = 0x0000d4
	DATA        = 0x0000f5
)

type Logger struct {
	log      *log.Logger
	modifier func(string) string
	filter   func(string) bool
}

func (l *Logger) Printf(format string, s ...interface{}) {
	expr := fmt.Sprintf(format, s...)
	l.Println(expr)
}

func (l *Logger) Println(s ...interface{}) {
	expr := fmt.Sprint(s...)
	if l.modifier != nil {
		expr = l.modifier(expr)
	}
	if l.filter != nil {
		if l.filter(expr) == true {
			return
		}
	}
	l.log.Println(expr)
}

var info = &Logger{
	log.New(stdio.Out, "\r[+]", log.Ldate|log.Ltime),
	nil,
	nil,
}

var warn = &Logger{
	log.New(stdio.Out, "\r[*]", log.Ldate|log.Ltime),
	nil,
	nil,
}

var err = &Logger{
	log.New(io.MultiWriter(stdio.Err), "\rERROR:", 0),
	nil,
	nil,
}

var dbg = &Logger{
	log.New(stdio.Out, "\r[-]", log.Ldate|log.Ltime),
	debugModifier,
	debugFilter,
}

func debugModifier(s string) string {
	_, file, line, _ := runtime.Caller(3)
	file = file[strings.LastIndex(file, "/")+1:]
	logStr := fmt.Sprintf("%s%s(%d) %s", "> ", file, line, s)
	return logStr
}

func debugFilter(s string) bool {
	if strings.Contains(s, "too many open") {
		err.Println("too many open files, lower the thread count or run \"ulimit -n 50000\"")
		os.Exit(0)
	}
	return false
}

var data = &Logger{
	log.New(stdio.Out, "\r", 0),
	nil,
	nil,
}

func Printf(level Level, format string, s ...interface{}) {
	Println(level, fmt.Sprintf(format, s...))
}

func Println(level Level, s ...interface{}) {
	logStr := fmt.Sprint(s...)
	switch level {
	case DEBUG:
		dbg.Println(logStr)
	case INFO:
		info.Println(logStr)
	case WARN:
		warn.Println(logStr)
	case ERROR:
		err.Println(logStr)
		os.Exit(1)
	case DATA:
		data.Println(logStr)
	default:
		return
	}
}

var empty = &Logger{log.New(io.Discard, "", 0), nil, nil}

func SetLevel(level Level) {
	if level > ERROR {
		err = empty
	}
	if level > WARN {
		warn = empty
	}
	if level > INFO {
		info = empty
	}
	if level > DEBUG {
		dbg = empty
	}
	if level > DATA {
		data = empty
	}
}
