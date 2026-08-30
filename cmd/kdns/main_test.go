// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/daemon"
)

func TestRun_Lifecycle(t *testing.T) {
	t.Run("HelpFlag", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), []string{"-help"}, &stdout, &stderr)
		require.ErrorIs(t, err, flag.ErrHelp)
		assert.Contains(t, stderr.String(), "Usage of kdns:")
		assert.Contains(t, stderr.String(), "-address")
	})

	t.Run("UnknownFlag_ReturnsGenericErrorNotHelp", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), []string{"-unknown-flag-xyz"}, &stdout, &stderr)
		require.Error(t, err)
		assert.False(t, errors.Is(err, flag.ErrHelp), "unknown flag should not return flag.ErrHelp")
		assert.Contains(t, stderr.String(), "flag provided but not defined: -unknown-flag-xyz")
	})

	t.Run("InvalidFlagValue_ReturnsGenericErrorNotHelp", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), []string{"-rrl-rate", "notanumber"}, &stdout, &stderr)
		require.Error(t, err)
		assert.False(t, errors.Is(err, flag.ErrHelp), "invalid flag value should not return flag.ErrHelp")
		assert.Contains(t, stderr.String(), "invalid value")
	})

	t.Run("InvalidStorageDir", func(t *testing.T) {
		invalidFilePath := filepath.Join(t.TempDir(), "invalid-file")
		require.NoError(t, os.WriteFile(invalidFilePath, []byte("not-a-directory"), 0o600))

		var stdout, stderr bytes.Buffer
		err := run(t.Context(), []string{"-storage-dir", invalidFilePath}, &stdout, &stderr)
		require.Error(t, err)
	})

	t.Run("ShortAPITokenFailsFast", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), []string{
			"-address", "127.0.0.1:0",
			"-http-addr", "127.0.0.1:0",
			"-api-token", "too-short",
		}, &stdout, &stderr)
		require.ErrorIs(t, err, daemon.ErrAPITokenTooShort)
		assert.Contains(t, stdout.String(), `"level":"ERROR"`)
		assert.Contains(t, stdout.String(), `"msg":"server startup failed"`)
		assert.Contains(t, stdout.String(), `"error":"api token must be at least 16 characters long`)
	})

	t.Run("ShortAPITokenFailsFast_TextFormat", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), []string{
			"-address", "127.0.0.1:0",
			"-http-addr", "127.0.0.1:0",
			"-api-token", "too-short",
			"-log-format", "text",
		}, &stdout, &stderr)
		require.ErrorIs(t, err, daemon.ErrAPITokenTooShort)
		assert.Contains(t, stdout.String(), "level=ERROR")
		assert.Contains(t, stdout.String(), `msg="server startup failed"`)
		assert.Contains(t, stdout.String(), `error="api token must be at least 16 characters long`)
	})

	t.Run("EmptyCORSOriginFailsFast", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), []string{
			"-address", "127.0.0.1:0",
			"-http-addr", "127.0.0.1:0",
			"-api-token", "valid-secret-token-12345",
			"-http-cors-origin", "",
		}, &stdout, &stderr)
		require.ErrorIs(t, err, daemon.ErrEmptyCORSOrigin)
	})

	t.Run("FullServerLifecycle", func(t *testing.T) {
		storageDir := filepath.Join(t.TempDir(), "data")
		require.NoError(t, os.MkdirAll(storageDir, 0o750))

		zoneFilePath := filepath.Join(storageDir, "example.zone")
		require.NoError(t, os.WriteFile(zoneFilePath, []byte("example.com. 300 IN A 1.2.3.4\n"), 0o600))

		var stdout, stderr bytes.Buffer

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			errCh <- run(ctx, []string{
				"-address", "127.0.0.1:0",
				"-http-addr", "127.0.0.1:0",
				"-api-token", "secret-api-token-1234",
				"-storage-dir", storageDir,
				"-zone-file", "example.zone",
				"-debug=true",
			}, &stdout, &stderr)
		}()

		time.Sleep(150 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("server run did not shut down within timeout")
		}

		assert.Contains(t, stdout.String(), "starting kdns server")
		assert.Contains(t, stdout.String(), "shutdown complete")
	})
}
