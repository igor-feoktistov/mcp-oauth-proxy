package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/example/mcp-oauth-proxy/internal/auth"
	"github.com/example/mcp-oauth-proxy/internal/authz"
	"github.com/example/mcp-oauth-proxy/internal/config"
	"github.com/example/mcp-oauth-proxy/internal/proxy"
)

// Server is the HTTP front end that authenticates MCP clients and forwards
// authorized traffic to the upstream MCP server.
type Server struct {
	cfg       *config.Config
	oauth2    *config.OAuth2
	keySets   map[string]*auth.KeySet
	primary   string
	dir       *directory
	validator *auth.Validator
	policy    *authz.Policy
	upstream  http.Handler
	logger    *slog.Logger
	metrics   *metrics
	registry  *prometheus.Registry

	externalBase string
	resourcePath string
}

// New assembles a Server from configuration, resolving display-name group
// aliases against the directory before the first request is served.
func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Server, error) {
	return newWithGraph(ctx, cfg, defaultGraphFactory, logger)
}

func newWithGraph(ctx context.Context, cfg *config.Config, factory GraphFactory, logger *slog.Logger) (*Server, error) {
	resource, err := url.Parse(cfg.Authorization.OAuth2.Resource)
	if err != nil {
		return nil, fmt.Errorf("parse authorization.oauth2.resource: %w", err)
	}

	rules, err := authz.LoadRules(cfg)
	if err != nil {
		return nil, err
	}

	dir := buildDirectory(cfg, factory, logger)

	canonical, aliases, err := groupRefs(cfg, rules, dir, logger)
	if err != nil {
		return nil, fmt.Errorf("resolve group references: %w", err)
	}

	allowGroups := make([]string, 0, len(cfg.Authorization.OAuth2.AllowGroups))
	for _, ref := range cfg.Authorization.OAuth2.AllowGroups {
		id, ok := canonical[strings.TrimSpace(ref)]
		if !ok {
			return nil, fmt.Errorf("allowGroups entry %q was not resolved to a group reference", ref)
		}
		allowGroups = append(allowGroups, id)
	}

	policy, err := authz.Compile(rules, canonical)
	if err != nil {
		return nil, err
	}

	validator, keySets, err := buildValidator(cfg, dir, allowGroups, aliases, logger)
	if err != nil {
		return nil, err
	}

	registry := prometheus.NewRegistry()
	s := &Server{
		cfg:          cfg,
		oauth2:       &cfg.Authorization.OAuth2,
		keySets:      keySets,
		primary:      strings.ToLower(cfg.Authorization.OAuth2.OAuth2Clients[0].TenantID),
		dir:          dir,
		validator:    validator,
		policy:       policy,
		upstream:     proxy.New(cfg.Upstream.ParsedURL(), cfg.Upstream.Timeout, cfg.Server.MaxGroupsHeaderBytes, logger),
		logger:       logger,
		metrics:      newMetrics(registry),
		registry:     registry,
		externalBase: resource.Scheme + "://" + resource.Host,
		resourcePath: resource.Path,
	}
	if dir != nil {
		registry.MustRegister(newGraphCollector(dir))
	}
	return s, nil
}

// Start primes every tenant's signing key cache.
func (s *Server) Start(ctx context.Context) error {
	for tenant, keys := range s.keySets {
		if err := keys.Prime(ctx); err != nil {
			return fmt.Errorf("tenant %s: %w", tenant, err)
		}
	}
	return nil
}

// StartRefresh begins background signing key refresh for every tenant. It takes
// the long-lived context so that refresh outlives the startup deadline.
func (s *Server) StartRefresh(ctx context.Context) error {
	for _, keys := range s.keySets {
		keys.StartRefresh(ctx)
	}
	return nil
}

// primaryDiscovery returns the discovery document of the first configured tenant.
func (s *Server) primaryDiscovery() *auth.DiscoveryDocument {
	if keys, ok := s.keySets[s.primary]; ok {
		return keys.Discovery()
	}
	return nil
}

// Handler returns the public router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// RFC 9728 metadata must be reachable without a token, at both the root and
	// the path-aware location derived from the resource URI.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/", s.handleProtectedResourceMetadata)

	if s.oauth2.DCR.MirrorASMetadata != nil && *s.oauth2.DCR.MirrorASMetadata {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
		mux.HandleFunc("GET /.well-known/oauth-authorization-server/", s.handleAuthorizationServerMetadata)
		mux.HandleFunc("GET /.well-known/openid-configuration", s.handleAuthorizationServerMetadata)
	}
	if s.oauth2.DCR.Enabled {
		mux.HandleFunc("POST /register", s.handleRegister)
	}

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.Handle("/", s.authenticate(s.authorize(s.upstream)))

	return s.recoverPanic(s.observe(s.cors(mux)))
}

// MetricsHandler returns the private router exposing metrics and probes.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	for tenant, keys := range s.keySets {
		if !keys.Healthy() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not-ready",
				"reason": "signing keys have not been fetched for tenant " + tenant,
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// authenticate validates the bearer token and attaches the principal to the context.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		raw, authErr := auth.BearerToken(r.Header.Get("Authorization"))
		if authErr != nil {
			s.rejectAuth(w, r, authErr)
			return
		}
		principal, authErr := s.validator.Validate(r.Context(), raw)
		if authErr != nil {
			s.rejectAuth(w, r, authErr)
			return
		}

		s.logger.Debug("authenticated caller",
			"user", principal.Identity(),
			"tenant", principal.TenantID,
			"client_id", principal.ClientID,
			"app_only", principal.AppOnly,
			"groups", len(principal.Groups),
			"matched_group", principal.MatchedGroup,
		)
		next.ServeHTTP(w, r.WithContext(proxy.WithPrincipal(r.Context(), principal)))
	})
}

// authorize inspects the JSON-RPC payload and applies the MCP policy before forwarding.
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := proxy.PrincipalFrom(r.Context())
		if principal == nil || r.Method != http.MethodPost || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.Server.MaxBodyBytes+1))
		_ = r.Body.Close()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "could not read request body",
			})
			return
		}
		if int64(len(body)) > s.cfg.Server.MaxBodyBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error":             "invalid_request",
				"error_description": "request body exceeds the configured limit",
			})
			return
		}
		// Restore the body so the upstream MCP server sees the original bytes.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))

		requests, err := authz.ParseRequests(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "request body is not a valid JSON-RPC message",
			})
			return
		}

		for _, req := range requests {
			decision := s.policy.Evaluate(principal, req)
			if decision.Allowed {
				continue
			}
			s.metrics.denials.WithLabelValues(req.Method, decision.Rule).Inc()
			s.logger.Warn("mcp request denied",
				"user", principal.Identity(),
				"tenant", principal.TenantID,
				"mcp_method", req.Method,
				"tool", req.Tool,
				"rule", decision.Rule,
			)
			s.writeChallenge(w, r, &auth.Error{
				Code:   auth.CodeInsufficientScope,
				Status: http.StatusForbidden,
				Description: fmt.Sprintf("caller is not permitted to invoke %s%s (%s)",
					req.Method, toolSuffix(req.Tool), decision.Reason),
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func toolSuffix(tool string) string {
	if tool == "" {
		return ""
	}
	return " on " + tool
}

func (s *Server) rejectAuth(w http.ResponseWriter, r *http.Request, authErr *auth.Error) {
	s.metrics.authFailures.WithLabelValues(authErr.Code).Inc()
	s.logger.Info("authentication rejected",
		"code", authErr.Code,
		"description", authErr.Description,
		"remote", clientIP(r),
		"path", r.URL.Path,
		"error", authErr.Unwrap(),
	)
	s.writeChallenge(w, r, authErr)
}

// cors answers browser preflight requests. MCP clients running in a browser need
// the Mcp-Session-Id and WWW-Authenticate headers exposed to script.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.originAllowed(origin) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		} else if r.Method == http.MethodOptions && origin != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.Server.AllowedOrigins {
		if allowed == "*" || strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		s.metrics.inflight.Inc()
		defer s.metrics.inflight.Dec()

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		outcome := outcomeFor(rec.status)
		s.metrics.requests.WithLabelValues(r.Method, outcome, strconv.Itoa(rec.status)).Inc()
		s.metrics.duration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
	})
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
				s.logger.Error("panic while handling request", "path", r.URL.Path, "panic", rec)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func outcomeFor(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "unauthenticated"
	case status == http.StatusForbidden:
		return "denied"
	case status >= 500:
		return "error"
	case status >= 400:
		return "client_error"
	default:
		return "allowed"
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer so that the
// reverse proxy can flush SSE frames and clear write deadlines.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if host, _, ok := strings.Cut(fwd, ","); ok {
			return strings.TrimSpace(host)
		}
		return strings.TrimSpace(fwd)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ListenAndServe runs the public and metrics listeners until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	public := &http.Server{
		Addr:    s.cfg.Server.ListenAddr,
		Handler: s.Handler(),
		// No write timeout: SSE streams are long lived.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	private := &http.Server{
		Addr:              s.cfg.Server.MetricsAddr,
		Handler:           s.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		s.logger.Info("metrics listener started", "addr", private.Addr)
		if err := private.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("metrics listener: %w", err)
		}
	}()
	go func() {
		s.logger.Info("proxy listener started",
			"addr", public.Addr,
			"upstream", s.cfg.Upstream.URL,
			"resource", s.oauth2.Resource,
			"tls", s.cfg.Server.TLSCertFile != "",
		)
		var err error
		if s.cfg.Server.TLSCertFile != "" {
			err = public.ListenAndServeTLS(s.cfg.Server.TLSCertFile, s.cfg.Server.TLSKeyFile)
		} else {
			err = public.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy listener: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = private.Shutdown(shutdownCtx)
	return public.Shutdown(shutdownCtx)
}
