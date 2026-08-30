// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aoliveti/kdns/internal/state"
)

func FuzzStore_OpenWithCorruptedSnapshot(f *testing.F) {
	f.Add([]byte("KDNS\x01\x00\x00\x00\x01"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()

		snapPath := filepath.Join(tmpDir, snapFileName)
		_ = os.WriteFile(snapPath, data, 0o600)

		st := state.New(1024)
		s, err := Open(tmpDir, st, WithLogger(discardLogger))
		if err == nil {
			_ = s.Close()
		}
	})
}
