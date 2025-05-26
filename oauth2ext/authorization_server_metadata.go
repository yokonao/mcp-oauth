package oauth2ext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrNoOAuthMetadata is returned when no OAuth metadata is found at the specified URL
	ErrNoOAuthMetadata = errors.New("no OAuth metadata found at the specified URL")
)

// OAuthMetadata contains OAuth 2.0 Authorization Server Metadata, which is defined in RFC 8414 Section 2
// https://datatracker.ietf.org/doc/html/rfc8414#section-2
type OAuthMetadata struct {
	Issuer                                             string   `json:"issuer"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      string   `json:"token_endpoint,omitempty"`
	JwksURI                                            string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               string   `json:"service_documentation,omitempty"`
	UILocalesSupported                                 []string `json:"ui_locales_supported"`
	OpPolicyURI                                        string   `json:"op_policy_uri,omitempty"`
	OpTosURI                                           string   `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`
}

// FetchOAuthMetadata loads 8414 OAuth 2.0 Authorization Server Metadata
func FetchOAuthMetadata(ctx context.Context, metadataURL string, additionalHeaders map[string]string) (OAuthMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return OAuthMetadata{}, fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range additionalHeaders {
		req.Header.Set(key, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return OAuthMetadata{}, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return OAuthMetadata{}, ErrNoOAuthMetadata
	}

	if resp.StatusCode != http.StatusOK {
		return OAuthMetadata{}, fmt.Errorf("failed to load well-known OAuth metadata: status %d", resp.StatusCode)
	}

	var metadata OAuthMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return OAuthMetadata{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return metadata, nil
}
