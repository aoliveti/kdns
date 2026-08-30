// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package main provides the entrypoint for the kdns server.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aoliveti/kdns/internal/daemon"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

// run encapsulates the application lifecycle under the provided context to enable robust testing.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cliCfg, err := parseCLI(args, stderr)
	if err != nil {
		return err
	}

	logLevel := slog.LevelInfo
	if cliCfg.debug {
		logLevel = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.Handler(slog.NewJSONHandler(stdout, opts))
	if cliCfg.logFormat == "text" {
		handler = slog.NewTextHandler(stdout, opts)
	}
	logger := slog.New(handler)

	if err := daemon.Run(
		ctx,
		cliCfg.toDaemonConfig(),
		daemon.WithLogger(logger),
		daemon.WithBuildInfo(version, commit, buildTime),
	); err != nil {
		logger.Error("server startup failed", slog.String("error", err.Error()))
		return err
	}

	return nil
}
