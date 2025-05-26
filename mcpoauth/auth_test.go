package mcpoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yokonao/mcp-oauth/oauth2ext"
)

// setupMockOAuthServer creates a test server that simulates an OAuth server
func setupMockOAuthServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Handle OAuth metadata discovery
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		server := "http://" + r.Host
		metadata := oauth2ext.OAuthMetadata{
			Issuer:                server,
			AuthorizationEndpoint: server + "/custom/authorize",
			TokenEndpoint:         server + "/custom/token",
			RegistrationEndpoint:  server + "/custom/register",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	// Handle client registration
	mux.HandleFunc("/custom/register", func(w http.ResponseWriter, r *http.Request) {
		var clientMetadata oauth2ext.OAuthClientMetadata
		if err := json.NewDecoder(r.Body).Decode(&clientMetadata); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid_client_metadata","error_description":"%s"}`, err.Error())
			return
		}

		response := oauth2ext.OAuthClientInformationResponse{
			OAuthClientMetadata: clientMetadata,
			ClientID:            "test-client-id",
			ClientSecret:        "test-client-secret",
			ClientIDIssuedAt:    1590000000,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Handle token exchange
	mux.HandleFunc("/custom/token", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_request"}`)
			return
		}

		code := r.Form.Get("code")
		if code != "valid-auth-code" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}

		codeVerifier := r.Form.Get("code_verifier")
		if codeVerifier == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_request","error_description":"code_verifier required"}`)
			return
		}

		response := map[string]any{
			"access_token":  "test-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "test-refresh-token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Default 404 handler for all other paths
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(mux)
}

// setupMockOAuthServerWithoutMetadata creates a test server that simulates an OAuth server without metadata discovery
func setupMockOAuthServerWithoutMetadata(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Metadata endpoint returns 404
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Handle client registration using default path
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var clientMetadata oauth2ext.OAuthClientMetadata
		if err := json.NewDecoder(r.Body).Decode(&clientMetadata); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid_client_metadata","error_description":"%s"}`, err.Error())
			return
		}

		response := oauth2ext.OAuthClientInformationResponse{
			OAuthClientMetadata: clientMetadata,
			ClientID:            "test-client-id",
			ClientSecret:        "test-client-secret",
			ClientIDIssuedAt:    1590000000,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Handle token exchange using default path
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"access_token":  "test-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "test-refresh-token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Default 404 handler for all other paths
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(mux)
}

func TestConfig_Start_WithMetadata(t *testing.T) {
	mockServer := setupMockOAuthServer(t)
	defer mockServer.Close()

	cfg := Config{
		ServerURL: mockServer.URL,
		ClientMetadata: oauth2ext.OAuthClientMetadata{
			ClientName:    "Test Client",
			RedirectURIs:  []string{"https://client.example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scope:         "openid profile email",
		},
	}

	process, err := cfg.Start(context.Background())
	require.NoError(t, err)
	require.NotNil(t, process.oauth2cfg)

	// Verify OAuth2 config was set correctly
	assert.Equal(t, "test-client-id", process.oauth2cfg.ClientID)
	assert.Equal(t, "test-client-secret", process.oauth2cfg.ClientSecret)
	assert.Equal(t, "https://client.example.com/callback", process.oauth2cfg.RedirectURL)
	assert.Equal(t, []string{"openid", "profile", "email"}, process.oauth2cfg.Scopes)

	serverURL := "http://" + mockServer.Listener.Addr().String()
	assert.Equal(t, serverURL+"/custom/authorize", process.oauth2cfg.Endpoint.AuthURL)
	assert.Equal(t, serverURL+"/custom/token", process.oauth2cfg.Endpoint.TokenURL)
}

func TestConfig_Start_WithoutMetadata(t *testing.T) {
	mockServer := setupMockOAuthServerWithoutMetadata(t)
	defer mockServer.Close()

	cfg := Config{
		ServerURL: mockServer.URL,
		ClientMetadata: oauth2ext.OAuthClientMetadata{
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://client.example.com/callback"},
		},
	}

	process, err := cfg.Start(context.Background())
	require.NoError(t, err)
	require.NotNil(t, process.oauth2cfg)

	// Verify default endpoints are used when metadata discovery fails
	assert.Equal(t, mockServer.URL+DEFAULT_AUTHORIZATION_ENDPOINT_PATH, process.oauth2cfg.Endpoint.AuthURL)
	assert.Equal(t, mockServer.URL+DEFAULT_TOKEN_ENDPOINT_PATH, process.oauth2cfg.Endpoint.TokenURL)
}

func TestConfig_Start_FailedMetadataDiscovery(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a bad response for metadata
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}))
	defer mockServer.Close()

	cfg := Config{
		ServerURL: mockServer.URL,
		ClientMetadata: oauth2ext.OAuthClientMetadata{
			ClientName: "Test Client",
		},
	}

	_, err := cfg.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to discover OAuth metadata")
}

func TestConfig_Start_MetadataMissingEndpoints(t *testing.T) {
	t.Run("missing authorization endpoint", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/oauth-authorization-server" {
				server := "http://" + r.Host
				metadata := oauth2ext.OAuthMetadata{
					Issuer:               server,
					TokenEndpoint:        server + "/token",
					RegistrationEndpoint: server + "/register",
					// AuthorizationEndpoint is missing
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(metadata)
				return
			}
		}))
		defer mockServer.Close()

		cfg := Config{
			ServerURL:      mockServer.URL,
			ClientMetadata: oauth2ext.OAuthClientMetadata{},
		}

		_, err := cfg.Start(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "metadata does not contain authorization endpoint")
	})

	t.Run("missing token endpoint", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/oauth-authorization-server" {
				server := "http://" + r.Host
				metadata := oauth2ext.OAuthMetadata{
					Issuer:                server,
					AuthorizationEndpoint: server + "/authorize",
					RegistrationEndpoint:  server + "/register",
					// TokenEndpoint is missing
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(metadata)
				return
			}
		}))
		defer mockServer.Close()

		cfg := Config{
			ServerURL:      mockServer.URL,
			ClientMetadata: oauth2ext.OAuthClientMetadata{},
		}

		_, err := cfg.Start(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "metadata does not contain token endpoint")
	})

	t.Run("missing registration endpoint", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/oauth-authorization-server" {
				server := "http://" + r.Host
				metadata := oauth2ext.OAuthMetadata{
					Issuer:                server,
					AuthorizationEndpoint: server + "/authorize",
					TokenEndpoint:         server + "/token",
					// RegistrationEndpoint is missing
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(metadata)
				return
			}
		}))
		defer mockServer.Close()

		cfg := Config{
			ServerURL:      mockServer.URL,
			ClientMetadata: oauth2ext.OAuthClientMetadata{},
		}

		_, err := cfg.Start(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "metadata does not contain registration endpoint")
	})
}

func TestConfig_Start_FailedRegistration(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Without metadata
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Registration fails
		if r.URL.Path == "/register" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_redirect_uri"}`)
			return
		}
	}))
	defer mockServer.Close()

	cfg := Config{
		ServerURL: mockServer.URL,
		ClientMetadata: oauth2ext.OAuthClientMetadata{
			ClientName:   "Test Client",
			RedirectURIs: []string{"invalid-uri"},
		},
	}

	_, err := cfg.Start(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to register client")
}

func TestProcess_AuthCodeURL(t *testing.T) {
	mockServer := setupMockOAuthServer(t)
	defer mockServer.Close()

	cfg := Config{
		ServerURL: mockServer.URL,
		ClientMetadata: oauth2ext.OAuthClientMetadata{
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://client.example.com/callback"},
		},
	}

	process, err := cfg.Start(context.Background())
	require.NoError(t, err)

	authURL, verifier, err := process.AuthCodeURL("test-state")
	require.NoError(t, err)
	assert.NotEmpty(t, authURL)
	assert.NotEmpty(t, verifier)

	// Verify the auth URL contains required PKCE and state parameters
	assert.Contains(t, authURL, "state=test-state")
	assert.Contains(t, authURL, "code_challenge=")
	assert.Contains(t, authURL, "code_challenge_method=S256")
	assert.Contains(t, authURL, "access_type=offline")
	assert.Contains(t, authURL, "client_id=test-client-id")
}

func TestProcess_AuthCodeURL_Uninitialized(t *testing.T) {
	// Test when Process is not properly initialized
	process := Process{oauth2cfg: nil}
	_, _, err := process.AuthCodeURL("test-state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth2 config is not initialized")
}

func TestProcess_Exchange(t *testing.T) {
	mockServer := setupMockOAuthServer(t)
	defer mockServer.Close()

	cfg := Config{
		ServerURL: mockServer.URL,
		ClientMetadata: oauth2ext.OAuthClientMetadata{
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://client.example.com/callback"},
		},
	}

	process, err := cfg.Start(context.Background())
	require.NoError(t, err)

	// Get a verifier for the exchange
	_, verifier, err := process.AuthCodeURL("test-state")
	require.NoError(t, err)

	// Test successful token exchange
	token, err := process.Exchange(context.Background(), "valid-auth-code", verifier)
	require.NoError(t, err)
	assert.Equal(t, "test-access-token", token.AccessToken)
	assert.Equal(t, "test-refresh-token", token.RefreshToken)
	assert.Equal(t, "Bearer", token.TokenType)
}

func TestProcess_Exchange_InvalidCode(t *testing.T) {
	mockServer := setupMockOAuthServer(t)
	defer mockServer.Close()

	cfg := Config{
		ServerURL: mockServer.URL,
		ClientMetadata: oauth2ext.OAuthClientMetadata{
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://client.example.com/callback"},
		},
	}

	process, err := cfg.Start(context.Background())
	require.NoError(t, err)

	// Get a verifier for the exchange
	_, verifier, err := process.AuthCodeURL("test-state")
	require.NoError(t, err)

	// Test exchange with invalid code
	_, err = process.Exchange(context.Background(), "invalid-code", verifier)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to exchange authorization code")
}

func TestProcess_Exchange_Uninitialized(t *testing.T) {
	// Test when Process is not properly initialized
	process := Process{oauth2cfg: nil}
	_, err := process.Exchange(context.Background(), "code", "verifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth2 config is not initialized")
}
