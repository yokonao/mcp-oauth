package oauth2ext

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestOAuthClientInformationResponse_ToOAuth2Config(t *testing.T) {
	tests := []struct {
		name     string
		response OAuthClientInformationResponse
		want     *oauth2.Config
	}{
		{
			name: "basic configuration",
			response: OAuthClientInformationResponse{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				OAuthClientMetadata: OAuthClientMetadata{
					RedirectURIs: []string{"https://example.com/callback", "https://example.com/another-callback"},
					Scope:        "read write",
				},
			},
			want: &oauth2.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback", // Should use the first URI
				Scopes:       []string{"read", "write"},
			},
		},
		{
			name: "empty redirect URI",
			response: OAuthClientInformationResponse{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				OAuthClientMetadata: OAuthClientMetadata{
					Scope: "read",
				},
			},
			want: &oauth2.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "",
				Scopes:       []string{"read"},
			},
		},
		{
			name: "empty scope",
			response: OAuthClientInformationResponse{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				OAuthClientMetadata: OAuthClientMetadata{
					RedirectURIs: []string{"https://example.com/callback"},
				},
			},
			want: &oauth2.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.response.ToOAuth2Config()
			assert.Equal(t, tt.want, got, "ToOAuth2Config() returned unexpected result")
		})
	}
}

func TestRegisterClient(t *testing.T) {
	testRedirectURIs := []string{
		"https://example.com/callback",
		"https://example.com/another-callback",
	}

	testClientMetadatas := map[string]OAuthClientMetadata{
		"standard": {
			ClientName:              "Standard Test Client",
			RedirectURIs:            testRedirectURIs,
			GrantTypes:              []string{"authorization_code"},
			Scope:                   "read write",
			TokenEndpointAuthMethod: "client_secret_basic",
		},
		"complete": {
			ClientName:              "Complete Test Client",
			ClientURI:               "https://example.com",
			RedirectURIs:            testRedirectURIs,
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			Scope:                   "read write profile email",
			TokenEndpointAuthMethod: "client_secret_jwt",
			LogoURI:                 "https://example.com/logo.png",
			Contacts:                []string{"support@example.com", "admin@example.com"},
			TosURI:                  "https://example.com/tos",
			PolicyURI:               "https://example.com/privacy",
			SoftwareID:              "example-software-id-123",
			SoftwareVersion:         "1.0.0",
		},
	}

	testServerResponses := map[string]OAuthClientInformationResponse{
		"standard": {
			ClientID:     "generated-client-id",
			ClientSecret: "generated-client-secret",
			OAuthClientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{testRedirectURIs[0]},
				GrantTypes:   []string{"authorization_code"},
				Scope:        "read write",
			},
			ClientIDIssuedAt:      time.Now().Unix(),
			ClientSecretExpiresAt: time.Now().AddDate(0, 0, 30).Unix(),
		},
		"complete": {
			ClientID:     "generated-complete-client-id",
			ClientSecret: "generated-complete-client-secret",
			OAuthClientMetadata: OAuthClientMetadata{
				ClientName:              "Complete Test Client",
				ClientURI:               "https://example.com",
				RedirectURIs:            testRedirectURIs,
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				Scope:                   "read write profile email",
				TokenEndpointAuthMethod: "client_secret_jwt",
				LogoURI:                 "https://example.com/logo.png",
				Contacts:                []string{"support@example.com", "admin@example.com"},
				TosURI:                  "https://example.com/tos",
				PolicyURI:               "https://example.com/privacy",
				SoftwareID:              "example-software-id-123",
				SoftwareVersion:         "1.0.0",
			},
			ClientIDIssuedAt:      time.Now().Unix(),
			ClientSecretExpiresAt: time.Now().AddDate(0, 0, 90).Unix(),
		},
	}

	tests := []struct {
		name           string
		clientMetadata OAuthClientMetadata
		serverResponse func(w http.ResponseWriter)
		want           OAuthClientInformationResponse
	}{
		{
			name:           "200 OK",
			clientMetadata: testClientMetadatas["standard"],
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				response := testServerResponses["standard"]
				json.NewEncoder(w).Encode(response)
			},
			want: testServerResponses["standard"],
		},
		{
			name: "201 Created",
			clientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"authorization_code"},
				Scope:        "read write",
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
				w.Header().Set("Content-Type", "application/json")
				response := testServerResponses["complete"]
				json.NewEncoder(w).Encode(response)
			},
			want: testServerResponses["complete"],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup a mock HTTP server to simulate the OAuth 2.0 Dynamic Client Registration endpoint
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Reject unexpected methods or headers
				require.Equal(t, http.MethodPost, r.Method, "Expected POST request")
				require.Equal(t, "application/json", r.Header.Get("Content-Type"), "Expected Content-Type: application/json")

				// Check if the request body can be decoded into OAuthClientMetadata and matches the expected client metadata
				var receivedMetadata OAuthClientMetadata
				err := json.NewDecoder(r.Body).Decode(&receivedMetadata)
				require.NoError(t, err, "Failed to decode request body")
				defer r.Body.Close()

				tt.serverResponse(w)
			}))
			defer server.Close()

			got, err := RegisterClient(context.Background(), server.URL, tt.clientMetadata)

			assert.NoError(t, err, "RegisterClient() should not return an error")

			require.NotNil(t, got, "Response should not be nil")
			assert.Equal(t, tt.want, got, "Response does not match expected value")
		})
	}
}
func TestRegisterClient_Error(t *testing.T) {
	// エラーレスポンスのバリエーション
	testErrorResponses := map[string]map[string]interface{}{
		"invalidRedirectURI": {
			"error":             "invalid_redirect_uri",
			"error_description": "The redirect URI is not allowed by the client",
		},
		"invalidClientMetadata": {
			"error":             "invalid_client_metadata",
			"error_description": "The client metadata is invalid",
		},
		"unapprovedSoftwareStatement": {
			"error":             "unapproved_software_statement",
			"error_description": "The software statement was not approved",
		},
		"serverError": {
			"error":             "server_error",
			"error_description": "The authorization server encountered an unexpected condition",
		},
	}

	tests := []struct {
		name           string
		clientMetadata OAuthClientMetadata
		serverResponse func(w http.ResponseWriter)
		wantErr        string
	}{
		{
			name: "400 Bad Request - invalid redirect URI",
			clientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://invalid.example.com/callback"},
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusBadRequest)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(testErrorResponses["invalidRedirectURI"])
			},
			wantErr: "failed to register client: status 400 details: {\"error\":\"invalid_redirect_uri\",\"error_description\":\"The redirect URI is not allowed by the client\"}",
		},
		{
			name: "400 Bad Request - invalid client metadata",
			clientMetadata: OAuthClientMetadata{
				ClientName: "Invalid Client",
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusBadRequest)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(testErrorResponses["invalidClientMetadata"])
			},
			wantErr: "failed to register client: status 400 details: {\"error\":\"invalid_client_metadata\",\"error_description\":\"The client metadata is invalid\"}",
		},
		{
			name: "401 Unauthorized - unapproved software statement",
			clientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
				SoftwareID:   "invalid-software-id",
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(testErrorResponses["unapprovedSoftwareStatement"])
			},
			wantErr: "failed to register client: status 401 details: {\"error\":\"unapproved_software_statement\",\"error_description\":\"The software statement was not approved\"}",
		},
		{
			name: "500 Internal Server Error",
			clientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(testErrorResponses["serverError"])
			},
			wantErr: "failed to register client: status 500 details: {\"error\":\"server_error\",\"error_description\":\"The authorization server encountered an unexpected condition\"}",
		},
		{
			name: "404 Not Found",
			clientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("Not Found"))
			},
			wantErr: "failed to register client: status 404",
		},
		{
			name: "Empty response body",
			clientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusBadRequest)
				// No response body
			},
			wantErr: "failed to register client: status 400",
		},
		{
			name: "Invalid JSON response",
			clientMetadata: OAuthClientMetadata{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("{invalid json"))
			},
			wantErr: "failed to decode response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup a mock HTTP server to simulate the OAuth 2.0 Dynamic Client Registration endpoint
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Reject unexpected methods or headers
				require.Equal(t, http.MethodPost, r.Method, "Expected POST request")
				require.Equal(t, "application/json", r.Header.Get("Content-Type"), "Expected Content-Type: application/json")

				// Check if the request body can be decoded into OAuthClientMetadata
				var receivedMetadata OAuthClientMetadata
				err := json.NewDecoder(r.Body).Decode(&receivedMetadata)
				require.NoError(t, err, "Failed to decode request body")
				defer r.Body.Close()

				tt.serverResponse(w)
			}))
			defer server.Close()

			_, err := RegisterClient(context.Background(), server.URL, tt.clientMetadata)
			assert.Error(t, err, "RegisterClient() should return an error")
			assert.Contains(t, err.Error(), tt.wantErr, "Error message should contain expected string")
		})
	}

	t.Run("Network error", func(t *testing.T) {
		// 存在しないサーバーへのリクエスト
		_, err := RegisterClient(context.Background(), "http://non-existent-server.invalid/register", OAuthClientMetadata{})
		assert.Error(t, err, "RegisterClient() should return an error for non-existent server")
		assert.Contains(t, err.Error(), "failed to send request", "Error message should contain expected string")
	})

	t.Run("Context canceled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// リクエストを遅延させる
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("{}"))
		}))
		defer server.Close()

		// キャンセル可能なコンテキストを作成
		ctx, cancel := context.WithCancel(context.Background())

		// すぐにキャンセル
		cancel()

		_, err := RegisterClient(ctx, server.URL, OAuthClientMetadata{})
		assert.Error(t, err, "RegisterClient() should return an error when context is canceled")
	})
}
