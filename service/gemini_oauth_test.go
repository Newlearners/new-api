package service

import (
	"net/url"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/require"
)

func TestGeminiOAuthKeyAcceptsGoogleAuthorizedUserAliases(t *testing.T) {
	raw := `{
		"type": "authorized_user",
		"token": "access-token",
		"refresh_token": "refresh-token",
		"client_id": "client-id",
		"client_secret": "client-secret",
		"quota_project_id": "project-123",
		"expiry": "2026-01-02T03:04:05Z"
	}`

	var key GeminiOAuthKey
	require.NoError(t, common.Unmarshal([]byte(raw), &key))
	key.normalize()

	require.Equal(t, GeminiOAuthCredentialType, key.Type)
	require.Equal(t, "access-token", key.AccessToken)
	require.Equal(t, "refresh-token", key.RefreshToken)
	require.Equal(t, "client-id", key.ClientID)
	require.Equal(t, "client-secret", key.ClientSecret)
	require.Equal(t, "project-123", key.ProjectID)
	require.Equal(t, "project-123", key.QuotaProject)
	require.Equal(t, "2026-01-02T03:04:05Z", key.ExpiresAt)
}

func TestCreateGeminiOAuthAuthorizationFlowUsesOfflinePKCE(t *testing.T) {
	flow, err := CreateGeminiOAuthAuthorizationFlow("client-id", "", "")
	require.NoError(t, err)

	authorizeURL, err := url.Parse(flow.AuthorizeURL)
	require.NoError(t, err)
	query := authorizeURL.Query()

	require.Equal(t, GeminiOAuthAuthorizeURL, authorizeURL.Scheme+"://"+authorizeURL.Host+authorizeURL.Path)
	require.Equal(t, "client-id", query.Get("client_id"))
	require.Equal(t, GeminiOAuthDefaultRedirectURI, query.Get("redirect_uri"))
	require.Equal(t, GeminiOAuthDefaultScope, query.Get("scope"))
	require.Equal(t, "offline", query.Get("access_type"))
	require.Equal(t, "consent", query.Get("prompt"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("code_challenge"))
	require.NotEmpty(t, query.Get("state"))
	require.NotEmpty(t, flow.Verifier)
}

func TestGeminiOAuthCredentialNeedsRefresh(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)

	require.True(t, GeminiOAuthCredentialNeedsRefresh(&GeminiOAuthKey{}, now))
	require.True(t, GeminiOAuthCredentialNeedsRefresh(&GeminiOAuthKey{
		AccessToken:  "token",
		RefreshToken: "refresh",
		ExpiresAt:    now.Add(4 * time.Minute).Format(time.RFC3339),
	}, now))
	require.False(t, GeminiOAuthCredentialNeedsRefresh(&GeminiOAuthKey{
		AccessToken:  "token",
		RefreshToken: "refresh",
		ExpiresAt:    now.Add(time.Hour).Format(time.RFC3339),
	}, now))
}
