// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package core_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"Zack-LocalScan/pkg/grdp/core"
)

func TestWriteUInt16LE(t *testing.T) {
	buff := &bytes.Buffer{}
	core.WriteUInt32LE(66538, buff)
	result := hex.EncodeToString(buff.Bytes())
	expected := "ea030100"
	if result != expected {
		t.Error(result, "not equals to", expected)
	}
}
