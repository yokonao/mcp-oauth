package oauth2ext

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// OAuthClientMetadata contains metadata about an OAuth client, which is defined in RFC 7591 Section 2
// https://datatracker.ietf.org/doc/html/rfc7591#section-2
type OAuthClientMetadata struct {
	// Array of redirection URI strings for use in redirect-based flows
	// such as the authorization code and implicit flows.  As required by
	// Section 2 of OAuth 2.0 [RFC6749], clients using flows with
	// redirection MUST register their redirection URI values.
	// Authorization servers that support dynamic registration for
	// redirect-based flows MUST implement support for this metadata
	// value.
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// String indicator of the requested authentication method for the token endpoint.
	// e.g. "none", "client_secret_basic", "client_secret_post" etc.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// Array of OAuth 2.0 grant type strings that the client can use at the token endpoint
	// e.g. "authorization_code", "implicit", "password", "client_credentials", "refresh_token" etc
	// If omitted, the default behavior is that the client will use only the "authorization_code" Grant Type.
	GrantTypes []string `json:"grant_types,omitempty"`
	// Array of the OAuth 2.0 response type strings that the client can use at the authorization endpoint.
	// e.g. "code", "token"
	// If omitted, the default is that the client will use only the "code" response type.
	ResponseTypes []string `json:"response_types,omitempty"`
	// Human-readable string name of the client to be presented to the end-user during authorization.
	// If omitted, the authorization server MAY display the raw "client_id" value to the end-user instead.
	// It is RECOMMENDED that clients always send this field.
	ClientName string `json:"client_name,omitempty"`
	// URL string of a web page providing information about the client.
	// If present, the server SHOULD display this URL to the end-user in a clickable fashion.
	// It is RECOMMENDED that clients always send this field.
	// The value of this field MUST point to a valid web page.
	ClientURI string `json:"client_uri,omitempty"`
	// URL string that references a logo for the client.
	// If present, the server SHOULD display this image to the end-user during approval.
	// The value of this field MUST point to a valid image file.
	LogoURI string `json:"logo_uri,omitempty"`
	// String containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749])
	// that the client can use when requesting access tokens.
	// The semantics of values in this list are service specific.
	// If omitted, an authorization server MAY register a client with a default set of scopes.
	Scope string `json:"scope,omitempty"`
	// Array of strings representing ways to contact people responsible for this client, typically email addresses.
	// The authorization server MAY make these contact addresses available to end-users for support requests for the client.
	Contacts []string `json:"contacts,omitempty"`
	// URL string that points to a human-readable terms of service document for the client
	// that describes a contractual relationship between the end-user and the client that the end-user accepts when
	// authorizing the client.
	// The authorization server SHOULD display this URL to the end-user if it is provided.
	// The value of this field MUST point to a valid web page.
	TosURI string `json:"tos_uri,omitempty"`
	// URL string that points to a human-readable privacy policy document that describes
	// how the deployment organization collects, uses, retains, and discloses personal data.
	// The authorization server SHOULD display this URL to the end-user if it is provided.
	// The value of this field MUST point to a valid web page.
	PolicyURI string `json:"policy_uri,omitempty"`
	// URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's public keys.
	// The value of this field MUST point to a valid JWK Set document.
	JwksURI string `json:"jwks_uri,omitempty"`
	// Client's JSON Web Key Set [RFC7517] document value, which contains the client's public keys.
	// The value of this field MUST be a JSON object containing a valid JWK Set.
	Jwks json.RawMessage `json:"jwks,omitempty"`
	// A unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer or software publisher
	// used by registration endpoints to identify the client software to be dynamically registered.
	// Unlike "client_id", which is issued by the authorization server and SHOULD vary between instances,
	// the "software_id" SHOULD remain the same for all instances of the client software.
	// The "software_id" SHOULD remain the same across multiple updates or versions of the same piece of software.
	// The value of this field is not intended to be human readable and is usually opaque to the client and authorization server.
	SoftwareID string `json:"software_id,omitempty"`
	// A version identifier string for the client software identified by "software_id".
	// The value of the "software_version" SHOULD change on any update to the client software identified by the same "software_id".
	SoftwareVersion string `json:"software_version,omitempty"`
	// A software statement containing client metadata values about the client software as claims.
	// This is a string value containing the entire signed JWT.
	SoftwareStatement json.RawMessage `json:"software_statement,omitempty"`
}

// OAuthClientInformationResponse contains client identifiers and metadata.
// This response is defined in RFC 7591 Section 3.2.1
// https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
type OAuthClientInformationResponse struct {
	OAuthClientMetadata

	// OAuth 2.0 client identifier string
	ClientID string `json:"client_id"`
	// OAuth 2.0 client secret string
	ClientSecret string `json:"client_secret,omitempty"`
	// Time at which the client identifier was issued.
	// The time is represented as the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time of issuance.
	ClientIDIssuedAt int64 `json:"client_id_issued_at,omitempty"`
	// Time at which the client secret will expire or 0 if it will not expire.
	// The time is represented as the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time of expiration.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`
}

func (r OAuthClientInformationResponse) ToOAuth2Config() *oauth2.Config {
	cfg := &oauth2.Config{
		ClientID:     r.ClientID,
		ClientSecret: r.ClientSecret,
	}
	if len(r.RedirectURIs) > 0 {
		cfg.RedirectURL = r.RedirectURIs[0] // Assuming that the first redirect URI is the primary one
	}
	if r.Scope != "" {
		cfg.Scopes = strings.Split(r.Scope, " ") // Split scope string into slice
	}

	return cfg
}

// RegisterClient performs OAuth 2.0 Dynamic Client Registration according to RFC 7591
func RegisterClient(ctx context.Context, registrationURL string, clientMetadata OAuthClientMetadata) (OAuthClientInformationResponse, error) {
	metadataJSON, err := json.Marshal(clientMetadata)
	if err != nil {
		return OAuthClientInformationResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewBuffer(metadataJSON))
	if err != nil {
		return OAuthClientInformationResponse{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return OAuthClientInformationResponse{}, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// [INFO] RFC 7591 Section 3.2.2 defines the 400 response format
		// https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
		errmsg := fmt.Sprintf("failed to register client: status %d", resp.StatusCode)
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			respBody = []byte("failed to read response body")
		}
		if len(respBody) > 0 {
			errmsg += fmt.Sprintf(" details: %s", string(respBody))
		}
		return OAuthClientInformationResponse{}, errors.New(errmsg)
	}

	var res OAuthClientInformationResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return OAuthClientInformationResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return res, nil
}
