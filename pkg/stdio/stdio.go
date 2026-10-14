// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package stdio

import (
	"Zack-LocalScan/pkg/stdio/chinese"
	"os"
)

var (
	Out = &Writer{out: os.Stdout}
	Err = &Writer{out: os.Stderr}
)

const (
	utf8 = 0x00000a1
	gbk  = 0x00000b2
)

var encoding = utf8

type Writer struct {
	out *os.File
}

func init() {
	if os.Getenv("ZACK_ENCODING") == "gbk" || os.Getenv("ZACK_ENCODING") == "gb2312" {
		encoding = gbk
	}
}

var quiet bool

// SetQuiet enables or disables silent mode. When silent, terminal output is suppressed.
func SetQuiet(b bool) {
	quiet = b
}

func (w *Writer) Write(p []byte) (n int, err error) {
	// In quiet mode, skip terminal output
	if quiet {
		return len(p), nil
	}

	var b []byte
	if encoding == utf8 {
		b = chinese.ByteToUTF8(p)
	} else {
		b = chinese.ByteToGBK(p)
	}
	return w.out.Write(b)
}
