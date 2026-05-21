package service

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/require"
)

func TestCodexOAuthKeyUnmarshalAliases(t *testing.T) {
	raw := `{
		"idToken": "id-top",
		"accessToken": "access-top",
		"refreshToken": "refresh-top",
		"sessionToken": "session-top",
		"accountId": "account-top",
		"lastRefresh": "2026-05-11T12:00:00Z",
		"expiresAt": "2026-05-12T12:00:00Z"
	}`

	var key CodexOAuthKey
	require.NoError(t, common.Unmarshal([]byte(raw), &key))

	require.Equal(t, "id-top", key.IDToken)
	require.Equal(t, "access-top", key.AccessToken)
	require.Equal(t, "refresh-top", key.RefreshToken)
	require.Equal(t, "session-top", key.SessionToken)
	require.Equal(t, "account-top", key.AccountID)
	require.Equal(t, "2026-05-11T12:00:00Z", key.LastRefresh)
	require.Equal(t, "2026-05-12T12:00:00Z", key.Expired)
}

func TestCodexOAuthKeyUnmarshalOpenAIOAuthFallback(t *testing.T) {
	raw := `{
		"session_token": "session-canonical",
		"openaiOauth": {
			"idToken": "id-nested",
			"accessToken": "access-nested",
			"refreshToken": "refresh-nested",
			"sessionToken": "session-nested"
		}
	}`

	var key CodexOAuthKey
	require.NoError(t, common.Unmarshal([]byte(raw), &key))

	require.Equal(t, "id-nested", key.IDToken)
	require.Equal(t, "access-nested", key.AccessToken)
	require.Equal(t, "refresh-nested", key.RefreshToken)
	require.Equal(t, "session-canonical", key.SessionToken)
}
