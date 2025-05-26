package oauth2ext

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchOAuthMetadata(t *testing.T) {
	// テスト用のOAuthメタデータ
	testMetadata := OAuthMetadata{
		Issuer:                 "https://auth.example.com",
		AuthorizationEndpoint:  "https://auth.example.com/oauth2/auth",
		TokenEndpoint:          "https://auth.example.com/oauth2/token",
		JwksURI:                "https://auth.example.com/.well-known/jwks.json",
		RegistrationEndpoint:   "https://auth.example.com/oauth2/register",
		ScopesSupported:        []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported: []string{"code", "token", "id_token", "code token", "code id_token"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token", "client_credentials"},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"client_secret_jwt",
		},
		RevocationEndpoint:            "https://auth.example.com/oauth2/revoke",
		IntrospectionEndpoint:         "https://auth.example.com/oauth2/introspect",
		CodeChallengeMethodsSupported: []string{"plain", "S256"},
	}

	t.Run("200 OK", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method, "Expected GET request")

			assert.Equal(t, "test-value", r.Header.Get("X-Test-Header"), "Expected X-Test-Header to be set")

			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(testMetadata))
		}))
		defer server.Close()

		additionalHeaders := map[string]string{
			"X-Test-Header": "test-value",
		}

		metadata, err := FetchOAuthMetadata(context.Background(), server.URL, additionalHeaders)

		require.NoError(t, err, "FetchOAuthMetadata() should not return an error")
		assert.Equal(t, testMetadata, metadata, "Metadata does not match expected value")
	})

	t.Run("404 Not Found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}))
		defer server.Close()

		// メタデータの取得試行
		_, err := FetchOAuthMetadata(context.Background(), server.URL, nil)

		// 特定のエラーが返されることを検証
		assert.ErrorIs(t, err, ErrNoOAuthMetadata, "Expected ErrNoOAuthMetadata error")
	})

	t.Run("500 Internal Server Error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}))
		defer server.Close()

		// メタデータの取得試行
		_, err := FetchOAuthMetadata(context.Background(), server.URL, nil)

		// エラーが返されることを検証
		assert.Error(t, err, "FetchOAuthMetadata() should return an error")
		assert.Contains(t, err.Error(), "failed to load well-known OAuth metadata: status 500", "Error should mention the status code")
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{invalid json"))
		}))
		defer server.Close()

		_, err := FetchOAuthMetadata(context.Background(), server.URL, nil)

		assert.Error(t, err, "FetchOAuthMetadata() should return an error")
		assert.Contains(t, err.Error(), "failed to decode response", "Error should mention decode failure")
	})

	t.Run("Network error", func(t *testing.T) {
		// 存在しないサーバーへのリクエスト
		_, err := FetchOAuthMetadata(context.Background(), "http://non-existent-server.invalid", nil)

		// エラーが返されることを検証
		assert.Error(t, err, "FetchOAuthMetadata() should return an error for non-existent server")
		assert.Contains(t, err.Error(), "failed to send request", "Error should mention request failure")
	})

	t.Run("Context canceled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// レスポンスを返さず処理を継続（クライアント側でタイムアウトさせるため）
			select {}
		}))
		defer server.Close()

		// Immediate context cancellation
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := FetchOAuthMetadata(ctx, server.URL, nil)

		assert.Error(t, err, "FetchOAuthMetadata() should return an error when context is canceled")
		assert.Contains(t, err.Error(), "context canceled", "Error should mention context cancellation")
	})
}
