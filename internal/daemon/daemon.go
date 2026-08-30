// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package daemon implements the central orchestrator for the KDNS server, managing
// background processes, listeners, configuration hot-reloading via SIGHUP,
// and graceful shutdown sequences.
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/aoliveti/kdns/internal/api"
	"github.com/aoliveti/kdns/internal/cluster/hub"
	"github.com/aoliveti/kdns/internal/cluster/replica"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/dnsserver"
	"github.com/aoliveti/kdns/internal/doh"
	"github.com/aoliveti/kdns/internal/metrics"
	"github.com/aoliveti/kdns/internal/state"
	"github.com/aoliveti/kdns/internal/store"
	"github.com/aoliveti/kdns/internal/tlsreload"
)

// Option configures functional parameters for the daemon runtime.
type Option func(*options)

type options struct {
	logger    *slog.Logger
	output    io.Writer
	version   string
	commit    string
	buildTime string
}

// WithLogger supplies a pre-configured logger to the daemon.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithOutput sets the output writer for daemon logs when using default logger.
func WithOutput(w io.Writer) Option {
	return func(o *options) {
		if w != nil {
			o.output = w
		}
	}
}

// WithBuildInfo configures version and build telemetry metadata.
func WithBuildInfo(version, commit, buildTime string) Option {
	return func(o *options) {
		o.version = version
		o.commit = commit
		o.buildTime = buildTime
	}
}

// Daemon represents the core application orchestrator.
type Daemon struct {
	logger    *slog.Logger
	telemetry *metrics.Metrics
	version   string
	commit    string
	buildTime string
	cfg       Config
}

// New constructs a Daemon instance configured with the specified options.
func New(cfg Config, opts ...Option) (*Daemon, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	opt := &options{
		output:    os.Stdout,
		version:   "dev",
		commit:    "unknown",
		buildTime: "unknown",
	}
	for _, o := range opts {
		o(opt)
	}

	logger := opt.logger
	if logger == nil {
		logger = buildLogger(cfg.Debug, opt.output)
	}

	mode := cfg.Cluster.Mode
	if mode == "" {
		mode = ModeStandalone
	}
	haEnabled := cfg.Cluster.Mode == ModePrimary || cfg.Cluster.Mode == ModeReplica

	serverID := cfg.Network.ServerID
	if serverID == "" {
		serverID = "none"
		if host, err := os.Hostname(); err == nil && host != "" {
			serverID = host
		}
		cfg.Network.ServerID = serverID
	}

	telemetry := metrics.New(
		metrics.WithBuildInfo(opt.version, opt.commit, opt.buildTime),
		metrics.WithServerInfo(
			string(mode),
			haEnabled,
			cfg.HasDNSSEC(),
			cfg.HasRRL(),
			cfg.HasTLS(),
			cfg.HasDoH(),
			cfg.Network.ServerID,
		),
	)

	return &Daemon{
		logger:    logger,
		telemetry: telemetry,
		version:   opt.version,
		commit:    opt.commit,
		buildTime: opt.buildTime,
		cfg:       cfg,
	}, nil
}

// Run creates a new Daemon instance and executes its lifecycle until context cancellation.
func Run(ctx context.Context, cfg Config, opts ...Option) error {
	d, err := New(cfg, opts...)
	if err != nil {
		return err
	}
	return d.Run(ctx)
}

// Run executes the daemon lifecycle blocking until context cancellation or a fatal error occurs.
func (d *Daemon) Run(ctx context.Context) (err error) {
	defer func() {
		if err == nil {
			d.logger.Info("shutdown complete")
		}
	}()

	mode := d.cfg.Cluster.Mode
	if mode == "" {
		mode = ModeStandalone
	}

	d.logger.Info(
		"starting kdns server",
		slog.String("version", d.version),
		slog.String("commit", d.commit),
		slog.String("build_time", d.buildTime),
		slog.String("mode", string(mode)),
		slog.String("server_id", d.cfg.Network.ServerID),
	)

	if d.cfg.Debug {
		d.logger.Debug("daemon runtime configuration",
			slog.String("dns_addr", d.cfg.Network.Address),
			slog.String("dot_addr", d.cfg.Network.DoTAddr),
			slog.String("doh_addr", d.cfg.Network.DoHAddr),
			slog.Bool("has_tls", d.cfg.HasTLS()),
			slog.String("server_id", d.cfg.Network.ServerID),
			slog.String("http_addr", d.cfg.HTTP.Addr),
			slog.String("cluster_mode", string(mode)),
			slog.String("cluster_addr", d.cfg.Cluster.Addr),
			slog.String("storage_dir", d.cfg.Storage.Dir),
			slog.String("zone_file", d.cfg.Storage.ZoneFile),
			slog.Bool("has_tsig", d.cfg.HasTSIG()),
			slog.Bool("has_dnssec", d.cfg.HasDNSSEC()),
			slog.Bool("has_rrl", d.cfg.HasRRL()),
		)
	}

	st := state.New(10000, state.WithMetrics(d.telemetry))

	storage, err := store.Open(d.cfg.Storage.Dir, st, d.cfg.StoreOptions(d.logger, d.telemetry)...)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	defer func() {
		if closeErr := storage.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close storage: %w", closeErr)
		}
	}()

	tlsCfg, reloader, tlsErr := d.initTLS()
	if tlsErr != nil {
		return tlsErr
	}

	d.logRRLStatus()

	srv, srvErr := d.buildDNSServer(st, storage, tlsCfg)
	if srvErr != nil {
		return srvErr
	}

	stop := context.AfterFunc(ctx, func() {
		d.logger.Info("received shutdown signal, initiating graceful shutdown")
	})
	defer stop()

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	d.startSignalReloader(ctx, &wg, reloader, storage, hupCh)

	wg.Go(func() {
		if srvErr := srv.Start(ctx); srvErr != nil && !errors.Is(srvErr, context.Canceled) {
			errCh <- fmt.Errorf("dns server: %w", srvErr)
		}
	})

	d.startDoH(ctx, &wg, errCh, st, tlsCfg)
	d.startCluster(ctx, &wg, errCh, st, storage)
	d.startHTTP(ctx, &wg, errCh, st, storage)

	wg.Wait()
	close(errCh)

	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// ErrTLSInitFailed indicates that TLS certificate initialization or loading failed.
var ErrTLSInitFailed = errors.New("daemon: failed to initialize tls")

// initTLS initializes dynamic certificate hot-reloading and returns the TLS configuration.
func (d *Daemon) initTLS() (*tls.Config, *tlsreload.Reloader, error) {
	if !d.cfg.HasTLS() {
		return nil, nil, nil
	}
	if d.cfg.Network.DoTAddr == "" {
		d.cfg.Network.DoTAddr = ":853"
	}
	reloader, err := tlsreload.New(d.cfg.TLS.CertPath, d.cfg.TLS.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrTLSInitFailed, err)
	}
	tlsCfg := &tls.Config{
		GetCertificate: reloader.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	d.logger.Info("tls configured successfully", slog.String("cert", d.cfg.TLS.CertPath))
	return tlsCfg, reloader, nil
}

// logRRLStatus logs the current response rate limiting operational parameters.
func (d *Daemon) logRRLStatus() {
	networkLogger := d.logger.With(slog.String("component", "network"))
	if d.cfg.HasRRL() {
		networkLogger.Info("response rate limiting enabled",
			slog.Int("rate", d.cfg.RRL.ResponsesPerSecond),
			slog.Int("error_rate", d.cfg.RRL.ErrorsPerSecond),
			slog.Int("slip", d.cfg.RRL.SlipRate),
			slog.Int("ipv4_prefix", d.cfg.RRL.IPv4Prefix),
			slog.Int("ipv6_prefix", d.cfg.RRL.IPv6Prefix),
		)
		return
	}
	networkLogger.Info("response rate limiting disabled")
}

// buildDNSServer constructs the core UDP/TCP/DoT DNS server instance with attached plugins.
func (d *Daemon) buildDNSServer(st *state.State, storage *store.Store, tlsCfg *tls.Config) (*dnsserver.Server, error) {
	networkLogger := d.logger.With(slog.String("component", "network"))
	srvOpts := []dnsserver.Option{
		dnsserver.WithAddress(d.cfg.Network.Address),
		dnsserver.WithLogger(networkLogger),
		dnsserver.WithMetrics(d.telemetry),
		dnsserver.WithVersion(d.version),
		dnsserver.WithIdentity(d.cfg.Network.ServerID),
		dnsserver.WithUpsertDeleter(storage),
	}
	if kr := d.cfg.KeyRing(); kr != nil {
		srvOpts = append(srvOpts, dnsserver.WithTSIG(kr))
		networkLogger.Info("tsig update authentication enabled",
			slog.Int("keys_count", len(d.cfg.TSIG.Keys)),
		)
	}
	dnssecMgr, dnssecErr := d.cfg.DNSSECManager()
	if dnssecErr != nil {
		return nil, fmt.Errorf("failed to initialize dnssec manager: %w", dnssecErr)
	}
	if dnssecMgr != nil {
		srvOpts = append(srvOpts, dnsserver.WithDNSSEC(dnssecMgr))
		networkLogger.Info("dnssec on-the-fly signing enabled")
	}
	if limiter := d.cfg.Limiter(); limiter != nil {
		srvOpts = append(srvOpts, dnsserver.WithRRL(limiter))
	}
	if tlsCfg != nil {
		srvOpts = append(
			srvOpts,
			dnsserver.WithTLSConfig(tlsCfg),
			dnsserver.WithDoTAddress(d.cfg.Network.DoTAddr),
		)
	}
	return dnsserver.New(st, srvOpts...), nil
}

// startSignalReloader listens for SIGHUP signals to perform zero-downtime certificate and storage reloads.
func (d *Daemon) startSignalReloader(ctx context.Context, wg *sync.WaitGroup, reloader *tlsreload.Reloader, storage *store.Store, hupCh <-chan os.Signal) {
	wg.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				d.logger.Info("received SIGHUP signal, initiating hot-reload")
				reloadFailed := false
				if reloader != nil {
					if relErr := reloader.Reload(); relErr != nil {
						d.logger.Error("failed to reload tls certificate", slog.Any("error", relErr))
						reloadFailed = true
					}
					if !reloadFailed {
						d.logger.Info("tls certificates reloaded successfully")
					}
				}
				if relErr := storage.ReloadState(); relErr != nil {
					d.logger.Error("failed to reload store state", slog.Any("error", relErr))
					reloadFailed = true
				}
				d.telemetry.IncReloadEvent(!reloadFailed)
			}
		}
	})
}

// startDoH starts the dedicated DNS-over-HTTPS (RFC 8484) server listener in a background goroutine.
func (d *Daemon) startDoH(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error, st *state.State, tlsCfg *tls.Config) {
	if !d.cfg.HasDoH() {
		return
	}
	dohLogger := d.logger.With(slog.String("component", "doh"))
	dohOpts := []doh.Option{
		doh.WithAddress(d.cfg.Network.DoHAddr),
		doh.WithLogger(dohLogger),
		doh.WithMetrics(d.telemetry),
	}
	if tlsCfg != nil {
		dohOpts = append(dohOpts, doh.WithTLSConfig(tlsCfg))
	}
	dohLogger.Info("starting doh server", slog.String("addr", d.cfg.Network.DoHAddr), slog.Bool("tls", tlsCfg != nil))
	dohSrv := doh.New(st, dohOpts...)
	wg.Go(func() {
		if dohErr := dohSrv.Start(ctx); dohErr != nil && !errors.Is(dohErr, context.Canceled) {
			errCh <- fmt.Errorf("doh server: %w", dohErr)
		}
	})
}

// startCluster launches the cluster replication subsystem (Hub server on primary or Replica client on replica).
func (d *Daemon) startCluster(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error, st *state.State, storage *store.Store) {
	switch d.cfg.Cluster.Mode {
	case ModePrimary:
		hubLogger := d.logger.With(slog.String("component", "cluster"))
		hubOpts := []hub.Option{
			hub.WithLogger(hubLogger),
			hub.WithMetrics(d.telemetry),
		}
		if d.cfg.Cluster.TLSCert != "" && d.cfg.Cluster.TLSKey != "" {
			tlsOpt, tlsErr := hub.WithTLS(d.cfg.Cluster.TLSCert, d.cfg.Cluster.TLSKey)
			if tlsErr != nil {
				errCh <- fmt.Errorf("cluster hub: %w", tlsErr)
				return
			}
			hubOpts = append(hubOpts, tlsOpt)
		}
		hubLogger.Info("starting cluster hub server",
			slog.String("addr", d.cfg.Cluster.Addr),
			slog.Bool("tls", d.cfg.Cluster.TLSCert != ""),
		)
		srv := hub.New(
			d.cfg.Cluster.Addr,
			d.cfg.Cluster.Token,
			storage,
			hubOpts...,
		)
		storage.SetClusterHub(srv)
		wg.Go(func() {
			if hubErr := srv.Start(ctx); hubErr != nil && !errors.Is(hubErr, context.Canceled) {
				errCh <- fmt.Errorf("cluster hub: %w", hubErr)
			}
		})
	case ModeReplica:
		replicaLogger := d.logger.With(slog.String("component", "replica"))
		repOpts := []replica.Option{
			replica.WithLogger(replicaLogger),
			replica.WithMetrics(d.telemetry),
		}
		tlsCfg, tlsErr := d.cfg.ReplicaTLSConfig()
		if tlsErr != nil {
			errCh <- fmt.Errorf("replica tls: %w", tlsErr)
			return
		}
		if tlsCfg != nil {
			repOpts = append(repOpts, replica.WithTLSConfig(tlsCfg))
		}
		replicaLogger.Info("starting replica sync client",
			slog.String("primary_url", d.cfg.Cluster.PrimaryURL),
			slog.Bool("tls", tlsCfg != nil),
		)
		client := replica.New(
			d.cfg.Cluster.PrimaryURL,
			d.cfg.Cluster.Token,
			d.cfg.Storage.Dir,
			st,
			repOpts...,
		)
		wg.Go(func() {
			if repErr := client.Start(ctx); repErr != nil && !errors.Is(repErr, context.Canceled) {
				errCh <- fmt.Errorf("replica client: %w", repErr)
			}
		})
	}
}

// startHTTP launches the control plane HTTP REST management API server.
func (d *Daemon) startHTTP(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error, st *state.State, storage *store.Store) {
	if !d.cfg.HasHTTP() {
		return
	}
	httpLogger := d.logger.With(slog.String("component", "api"))

	var upsertDeleter dns.UpsertDeleter = storage
	if d.cfg.Cluster.Mode == ModeReplica {
		upsertDeleter = nil // Read-only API in replica mode
	}

	httpLogger.Info("starting control plane api server",
		slog.String("addr", d.cfg.HTTP.Addr),
		slog.Bool("read_only", d.cfg.Cluster.Mode == ModeReplica),
	)

	apiOpts := []api.Option{
		api.WithUpsertDeleter(upsertDeleter),
		api.WithAddress(d.cfg.HTTP.Addr),
		api.WithLogger(httpLogger),
		api.WithMetrics(d.telemetry),
		api.WithAPIToken(d.cfg.HTTP.APIToken),
	}
	if !d.cfg.HTTP.CORS {
		apiOpts = append(apiOpts, api.WithoutCORS())
	}
	if d.cfg.HTTP.CORS && d.cfg.HTTP.CORSOrigin != "" {
		apiOpts = append(apiOpts, api.WithCORSOrigin(d.cfg.HTTP.CORSOrigin))
	}

	httpSrv := api.New(st, apiOpts...)
	wg.Go(func() {
		if httpErr := httpSrv.Start(ctx); httpErr != nil && !errors.Is(httpErr, context.Canceled) {
			errCh <- fmt.Errorf("http server: %w", httpErr)
		}
	})
}

func buildLogger(debug bool, w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{
		Level: level,
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
