// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package misc

import (
	"fmt"
)

func RemoveDuplicateElement[T any](slice []T, elems ...T) []T {
	slice = append(slice, elems...)
	set := make(map[string]struct{}, len(slice))
	j := 0
	for _, v := range slice {
		_, ok := set[fmt.Sprint(v)]
		if ok {
			continue
		}
		set[fmt.Sprint(v)] = struct{}{}
		slice[j] = v
		j++
	}
	return slice[:j]
}
