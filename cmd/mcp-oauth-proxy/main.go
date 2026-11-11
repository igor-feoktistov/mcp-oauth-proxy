// Command mcp-oauth-proxy is an OAuth 2.1 resource-server sidecar that puts
// Microsoft Entra ID authentication and directory-group authorization in front
// of an MCP server that has no OAuth support of its own.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	mcpoauthproxy "github.com/example/mcp-oauth-proxy"
	"github.com/example/mcp-oauth-proxy/internal/authz"
	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/graph"
	"github.com/example/mcp-oauth-proxy/internal/server"
)

// version is stamped at link time with -ldflags "-X main.version=...". It is
// deliberately left empty rather than given a default: the linker can only set
// a string variable that has no initializer or a constant one, so initializing
// it with a function call would silently undo -X at package init.
var version = ""

// buildVersion prefers the linker-stamped value, which lets a release pipeline
// append a commit or release-candidate suffix, and otherwise falls back to the
// embedded VERSION file so that `go run` and a plain `go build` report the real
// version instead of a placeholder.
func buildVersion() string {
	if v := strings.TrimSpace(version); v != "" {
		return v
	}
	if v := mcpoauthproxy.Version(); v != "" {
		return v
	}
	return "unknown"
}

func main() {
	var (
		configPath  = flag.String("config", "", "path to the YAML configuration file (defaults to $"+config.ConfigFileEnv+")")
		checkOnly   = flag.Bool("check-config", false, "validate the configuration and exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildVersion())
		return
	}

	if err := run(*configPath, *checkOnly); err != nil {
		// Name the version here too: a configuration error is raised before
		// there is a logger to carry it, and "which build produced this?" is
		// the first question asked of a crash-looping container.
		fmt.Fprintf(os.Stderr, "mcp-oauth-proxy %s: %v\n", buildVersion(), err)
		os.Exit(1)
	}
}

func run(configPath string, checkOnly bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger := newLogger(cfg).With("version", buildVersion())

	// Emit this before anything that can fail. The later "ready" record is only
	// reached once Entra ID's keys have been fetched, so a proxy that dies
	// during startup would otherwise never say what it was.
	logger.Info("mcp-oauth-proxy starting",
		"go", runtime.Version(),
		"platform", runtime.GOOS+"/"+runtime.GOARCH,
	)

	if checkOnly {
		if err := checkPolicy(cfg); err != nil {
			return err
		}
		fmt.Println("configuration is valid")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Group aliases are resolved against the directory during construction, so
	// give startup its own deadline rather than inheriting none.
	startCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	srv, err := server.New(startCtx, cfg, logger)
	if err != nil {
		return err
	}
	if err := srv.Start(startCtx); err != nil {
		return fmt.Errorf("prime Entra ID signing keys: %w", err)
	}
	// Background refresh must outlive the startup deadline.
	if err := srv.StartRefresh(ctx); err != nil {
		return err
	}

	logger.Info("mcp-oauth-proxy ready",
		"resource", cfg.Authorization.OAuth2.Resource,
		"upstream", cfg.Upstream.URL,
		"tenants", len(cfg.Authorization.OAuth2.OAuth2Clients),
		"listenAddr", cfg.Server.ListenAddr,
		"metricsAddr", cfg.Server.MetricsAddr,
	)

	if err := srv.ListenAndServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	logger.Info("mcp-oauth-proxy stopped")
	return nil
}

// checkPolicy compiles the policy offline so that a malformed rule is caught by
// --check-config rather than at rollout time. Display names are checked for
// syntax only; translating one into an object id needs the directory, and that
// happens on first use.
func checkPolicy(cfg *config.Config) error {
	policy, err := authz.LoadRules(cfg)
	if err != nil {
		return err
	}
	refs := append(authz.GroupRefs(policy), cfg.Authorization.OAuth2.AllowGroups...)
	canonical, err := graph.CanonicalRefs(refs)
	if err != nil {
		return err
	}
	if _, err := authz.Compile(policy, canonical); err != nil {
		return err
	}
	return nil
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Log.Format == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}
