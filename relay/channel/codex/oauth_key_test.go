package codex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseOAuthKeyAliases(t *testing.T) {
	key, err := ParseOAuthKey(`{
		"accessToken": "access-top",
		"refreshToken": "refresh-top",
		"sessionToken": "session-top",
		"accountID": "account-top"
	}`)

	require.NoError(t, err)
	require.Equal(t, "access-top", key.AccessToken)
	require.Equal(t, "refresh-top", key.RefreshToken)
	require.Equal(t, "session-top", key.SessionToken)
	require.Equal(t, "account-top", key.AccountID)
}

func TestParseOAuthKeyOpenAIOAuthFallback(t *testing.T) {
	key, err := ParseOAuthKey(`{
		"openaiOauth": {
			"accessToken": "access-nested",
			"refreshToken": "refresh-nested"
		}
	}`)

	require.NoError(t, err)
	require.Equal(t, "access-nested", key.AccessToken)
	require.Equal(t, "refresh-nested", key.RefreshToken)
}
