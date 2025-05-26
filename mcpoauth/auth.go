package mcpoauth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/yokonao/mcp-oauth/oauth2ext"
)

const (
	// LATEST_PROTOCOL_VERSION represents the latest MCP protocol version
	// This would normally be imported from a types package
	LATEST_PROTOCOL_VERSION = "2025-03-26"

	// https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-3-3-fallbacks-for-servers-without-metadata-discovery
	DEFAULT_AUTHORIZATION_ENDPOINT_PATH = "/authorize"
	// https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-3-3-fallbacks-for-servers-without-metadata-discovery
	DEFAULT_TOKEN_ENDPOINT_PATH = "/token"
	// https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-3-3-fallbacks-for-servers-without-metadata-discovery
	DEFAULT_REGISTRATION_ENDPOINT_PATH = "/register"
)

var (
	// MCP clients SHOULD include the header MCP-Protocol-Version: <protocol-version> during Server Metadata Discovery
	// to allow the MCP server to respond based on the MCP protocol version.
	// https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-3-1-server-metadata-discovery-headers
	serverMetadataDiscoveryHeaders = map[string]string{
		"MCP-Protocol-Version": LATEST_PROTOCOL_VERSION,
	}
)

type Config struct {
	// ServerURL is the URL of the OAuth authorization server
	ServerURL string

	// ClientMetadata returns metadata about this OAuth client
	ClientMetadata oauth2ext.OAuthClientMetadata
}

// Process orchestrates the OAuth 2.0 authorization flow as described in the MCP protocol.
// https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization
type Process struct {
	oauth2cfg *oauth2.Config
}

// Start initializes the OAuth 2.0 authorization flow.
// It discovers the OAuth metadata and registers the client.
//
// NOTE: This function ONLY supports dynamic client registration.
// We need implement another function to use pre-registered clients.
func (cfg Config) Start(ctx context.Context) (Process, error) {
	// Discover OAuth Metadata
	serverURL := cfg.ServerURL
	metadataURL := serverURL + "/.well-known/oauth-authorization-server"

	var authorizationURL, tokenURL, registrationURL string
	metadata, err := oauth2ext.FetchOAuthMetadata(ctx, metadataURL, serverMetadataDiscoveryHeaders)
	if err != nil {
		if err == oauth2ext.ErrNoOAuthMetadata {
			// If no metadata is found, use default endpoints
			authorizationURL = serverURL + DEFAULT_AUTHORIZATION_ENDPOINT_PATH
			tokenURL = serverURL + DEFAULT_TOKEN_ENDPOINT_PATH
			registrationURL = serverURL + DEFAULT_REGISTRATION_ENDPOINT_PATH
		} else {
			return Process{}, fmt.Errorf("failed to discover OAuth metadata: %w", err)
		}
	} else {
		if metadata.AuthorizationEndpoint != "" {
			authorizationURL = metadata.AuthorizationEndpoint
		} else {
			return Process{}, fmt.Errorf("incompatible auth server: metadata does not contain authorization endpoint")
		}
		if metadata.TokenEndpoint != "" {
			tokenURL = metadata.TokenEndpoint
		} else {
			return Process{}, fmt.Errorf("incompatible auth server: metadata does not contain token endpoint")
		}
		if metadata.RegistrationEndpoint != "" {
			registrationURL = metadata.RegistrationEndpoint
		} else {
			return Process{}, fmt.Errorf("incompatible auth server: metadata does not contain registration endpoint")
		}
	}

	res, err := oauth2ext.RegisterClient(ctx, registrationURL, cfg.ClientMetadata)
	if err != nil {
		return Process{}, fmt.Errorf("failed to register client: %w", err)
	}

	oauth2cfg := res.ToOAuth2Config()
	oauth2cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  authorizationURL,
		TokenURL: tokenURL,
	}

	return Process{oauth2cfg: oauth2cfg}, nil
}

// AuthCodeURL generates the authorization URL for the OAuth 2.0 flow.
// It returns the authorization URL, the code verifier, and any error encountered.
//
// NOTE: MCP Specification requires the use of PKCE (Proof Key for Code Exchange).
func (p *Process) AuthCodeURL(state string) (string, string, error) {
	if p.oauth2cfg == nil {
		return "", "", fmt.Errorf("oauth2 config is not initialized unexpectedly")
	}

	codeVerifier := oauth2.GenerateVerifier()
	authURL := p.oauth2cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(codeVerifier))
	return authURL, codeVerifier, nil
}

// Exchange converts an authorization code into a token.
// codeVerifier is required and used for PKCE (Proof Key for Code Exchange).
func (p *Process) Exchange(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error) {
	if p.oauth2cfg == nil {
		return nil, fmt.Errorf("oauth2 config is not initialized. Please call mcpauth.Start() first")
	}

	// Exchange the authorization code for tokens
	tokens, err := p.oauth2cfg.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return tokens, nil
}

// RefreshAuthorization exchanges a refresh token for an updated access token
// func RefreshAuthorization(
// 	authorizationServerURL *url.URL,
// 	metadata *OAuthMetadata,
// 	clientInfo OAuthClientInformation,
// 	refreshToken string,
// ) (OAuthTokens, error) {
// 	grantType := "refresh_token"

// 	var tokenURL *url.URL
// 	var err error

// 	if metadata != nil {
// 		tokenURL, err = url.Parse(metadata.TokenEndpoint)
// 		if err != nil {
// 			return OAuthTokens{}, err
// 		}

// 		// Check if server supports required grant type
// 		if metadata.GrantTypesSupported != nil {
// 			supportsGrantType := slices.Contains(metadata.GrantTypesSupported, grantType)
// 			if !supportsGrantType {
// 				return OAuthTokens{}, fmt.Errorf("incompatible auth server: does not support grant type %s", grantType)
// 			}
// 		}
// 	} else {
// 		tokenURL, err = url.Parse(authorizationServerURL.String() + "/token")
// 		if err != nil {
// 			return OAuthTokens{}, err
// 		}
// 	}

// 	// Prepare form data
// 	form := url.Values{}
// 	form.Set("grant_type", grantType)
// 	form.Set("client_id", clientInfo.ClientID)
// 	form.Set("refresh_token", refreshToken)

// 	if clientInfo.ClientSecret != "" {
// 		form.Set("client_secret", clientInfo.ClientSecret)
// 	}

// 	// Make the request
// 	resp, err := http.PostForm(tokenURL.String(), form)
// 	if err != nil {
// 		return OAuthTokens{}, err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		return OAuthTokens{}, fmt.Errorf("token refresh failed: HTTP %d", resp.StatusCode)
// 	}

// 	var tokens OAuthTokens
// 	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
// 		return OAuthTokens{}, err
// 	}

// 	// Preserve the refresh token if not returned in the response
// 	if tokens.RefreshToken == "" {
// 		tokens.RefreshToken = refreshToken
// 	}

// 	return tokens, nil
// }
