// Package proxy forwards authenticated requests to the unmodified MCP server.
package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/example/mcp-oauth-proxy/internal/auth"
)

type principalKey struct{}

// WithPrincipal stores the validated caller on the request context.
func WithPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom retrieves the validated caller from the request context.
func PrincipalFrom(ctx context.Context) *auth.Principal {
	p, _ := ctx.Value(principalKey{}).(*auth.Principal)
	return p
}

// identityHeaders are set by the proxy and stripped from inbound requests so a
// client can never spoof an identity to the upstream MCP server.
var identityHeaders = []string{
	"X-Mcp-Subject",
	"X-Mcp-User",
	"X-Mcp-User-Id",
	"X-Mcp-Tenant-Id",
	"X-Mcp-Client-Id",
	"X-Mcp-Roles",
	"X-Mcp-Groups",
	"X-Mcp-Groups-Truncated",
	"X-Mcp-Matched-Group",
	"X-Mcp-App-Only",
	"X-Forwarded-User",
	"X-Forwarded-Email",
}

// New builds a reverse proxy to upstream that streams responses without buffering,
// which is required for the MCP streamable HTTP and SSE transports.
func New(upstream *url.URL, timeout time.Duration, maxGroupsHeaderBytes int, logger *slog.Logger) *httputil.ReverseProxy {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// SSE responses must never be buffered or compressed by the proxy.
		DisableCompression:    true,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     upstream.Scheme == "https",
	}

	rp := &httputil.ReverseProxy{
		Transport: transport,
		// -1 flushes each write immediately, keeping SSE events real-time.
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = upstream.Host
			r.SetXForwarded()

			// Never forward the client's access token upstream: the MCP
			// specification forbids token passthrough.
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("Cookie")
			for _, h := range identityHeaders {
				r.Out.Header.Del(h)
			}

			if p := PrincipalFrom(r.In.Context()); p != nil {
				setIdentityHeaders(r.Out.Header, p, maxGroupsHeaderBytes)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				resp.Header.Set("Cache-Control", "no-cache, no-transform")
				resp.Header.Set("X-Accel-Buffering", "no")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				return // client disconnected
			}
			logger.Error("upstream request failed", "path", r.URL.Path, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"upstream MCP server unavailable"},"id":null}`))
		},
	}
	return rp
}

func setIdentityHeaders(h http.Header, p *auth.Principal, maxGroupsBytes int) {
	set := func(key, value string) {
		if value != "" {
			h.Set(key, value)
		}
	}
	set("X-Mcp-Subject", p.Subject)
	set("X-Mcp-User", p.Identity())
	set("X-Mcp-User-Id", p.ObjectID)
	set("X-Mcp-Tenant-Id", p.TenantID)
	set("X-Mcp-Client-Id", p.ClientID)
	set("X-Mcp-Roles", strings.Join(p.Roles, " "))
	set("X-Mcp-Matched-Group", p.MatchedGroup)
	if p.AppOnly {
		set("X-Mcp-App-Only", "true")
	}

	groups, truncated := capList(p.Groups, maxGroupsBytes)
	set("X-Mcp-Groups", groups)
	if truncated {
		// Transitive membership can run to hundreds of groups. Silently
		// dropping some would let the upstream make a wrong decision, so say so.
		set("X-Mcp-Groups-Truncated", "true")
	}
}

// capList joins values until the result would exceed max bytes. Ingress
// controllers commonly cap a single header at 4-8 KB and answer anything
// larger with a 502, so the proxy must bound what it forwards.
func capList(values []string, max int) (string, bool) {
	if max <= 0 {
		return "", len(values) > 0
	}
	var b strings.Builder
	for i, v := range values {
		extra := len(v)
		if i > 0 {
			extra++
		}
		if b.Len()+extra > max {
			return b.String(), true
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(v)
	}
	return b.String(), false
}
