// Package server wires authentication, authorization and proxying into an HTTP server.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/example/mcp-oauth-proxy/internal/auth"
)

// protectedResourceMetadata is the RFC 9728 document that lets an MCP client
// discover which authorization server protects this resource.
type protectedResourceMetadata struct {
	Resource                             string   `json:"resource"`
	AuthorizationServers                 []string `json:"authorization_servers"`
	ScopesSupported                      []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported               []string `json:"bearer_methods_supported"`
	ResourceSigningAlgValuesSupported    []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceName                         string   `json:"resource_name,omitempty"`
	ResourceDocumentation                string   `json:"resource_documentation,omitempty"`
	TLSClientCertificateBoundAccessToken bool     `json:"tls_client_certificate_bound_access_tokens"`
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	doc := protectedResourceMetadata{
		Resource:                          s.oauth2.Resource,
		AuthorizationServers:              []string{s.oauth2.AuthorizationServer()},
		ScopesSupported:                   s.oauth2.ScopesSupported,
		BearerMethodsSupported:            []string{"header"},
		ResourceSigningAlgValuesSupported: []string{"RS256"},
		ResourceName:                      s.oauth2.ResourceName,
		ResourceDocumentation:             s.oauth2.ResourceDocumentation,
	}
	writeJSON(w, http.StatusOK, doc)
}

// handleAuthorizationServerMetadata mirrors the Entra ID discovery document. Mirroring
// lets the proxy advertise a registration_endpoint, because Entra ID does not implement
// RFC 7591 dynamic client registration.
func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	doc := s.primaryDiscovery()
	if doc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":             "temporarily_unavailable",
			"error_description": "authorization server metadata has not been fetched yet",
		})
		return
	}

	var merged map[string]any
	if err := json.Unmarshal(doc.RawJSON, &merged); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "server_error"})
		return
	}
	if s.oauth2.DCR.Enabled {
		merged["registration_endpoint"] = s.externalURL(r, "/register")
	}
	writeJSON(w, http.StatusOK, merged)
}

type clientRegistrationRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scope        string   `json:"scope"`
}

type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
}

// handleRegister is a dynamic client registration shim. Entra ID has no open
// registration endpoint, so the proxy hands every client the same pre-provisioned
// public client id whose redirect URIs an administrator registered up front.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req clientRegistrationRequest
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req)
	}

	scope := req.Scope
	if scope == "" {
		scope = strings.Join(s.oauth2.ScopesSupported, " ")
	}
	writeJSON(w, http.StatusCreated, clientRegistrationResponse{
		ClientID:                s.oauth2.DCR.StaticClientID,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   scope,
	})
}

// writeChallenge emits an RFC 6750 / RFC 9728 challenge. The resource_metadata
// parameter is what allows an MCP client to bootstrap the OAuth flow by itself.
func (s *Server) writeChallenge(w http.ResponseWriter, r *http.Request, authErr *auth.Error) {
	params := []string{
		fmt.Sprintf("resource_metadata=%q", s.metadataURL(r)),
		fmt.Sprintf("error=%q", authErr.Code),
		fmt.Sprintf("error_description=%q", sanitizeQuoted(authErr.Description)),
	}
	if authErr.Code == auth.CodeInsufficientScope && len(s.oauth2.ScopesSupported) > 0 {
		params = append(params, fmt.Sprintf("scope=%q", strings.Join(s.oauth2.ScopesSupported, " ")))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))

	status := authErr.Status
	if status == 0 {
		status = http.StatusUnauthorized
	}
	writeJSON(w, status, map[string]string{
		"error":             authErr.Code,
		"error_description": authErr.Description,
	})
}

// metadataURL returns the path-aware RFC 9728 metadata location for this resource.
func (s *Server) metadataURL(r *http.Request) string {
	path := "/.well-known/oauth-protected-resource"
	if p := strings.Trim(s.resourcePath, "/"); p != "" {
		path += "/" + p
	}
	return s.externalURL(r, path)
}

func (s *Server) externalURL(r *http.Request, path string) string {
	return strings.TrimRight(s.externalBase, "/") + path
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
}

// sanitizeQuoted removes characters that would break the quoted-string syntax of
// the WWW-Authenticate header.
func sanitizeQuoted(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '"' || r == '\\':
			return -1
		case r < 0x20 || r == 0x7f:
			return ' '
		default:
			return r
		}
	}, s)
}
