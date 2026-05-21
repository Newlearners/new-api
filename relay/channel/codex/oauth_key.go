package codex

import (
	"errors"
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
)

type OAuthKey struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	SessionToken string `json:"session_token,omitempty"`

	AccountID   string `json:"account_id,omitempty"`
	LastRefresh string `json:"last_refresh,omitempty"`
	Email       string `json:"email,omitempty"`
	Type        string `json:"type,omitempty"`
	Expired     string `json:"expired,omitempty"`
}

func (k *OAuthKey) UnmarshalJSON(data []byte) error {
	type oauthKey OAuthKey
	var canonical oauthKey
	if err := common.Unmarshal(data, &canonical); err != nil {
		return err
	}

	*k = OAuthKey(canonical)

	var raw map[string]any
	if err := common.Unmarshal(data, &raw); err != nil {
		return err
	}
	k.applyAliasFields(raw)
	for _, nestedKey := range []string{"openaiOauth", "openai_oauth"} {
		if nested, ok := oauthNestedMap(raw, nestedKey); ok {
			k.applyAliasFields(nested)
		}
	}
	return nil
}

func (k *OAuthKey) applyAliasFields(raw map[string]any) {
	applyOAuthAlias(&k.IDToken, raw, "idToken", "id_token")
	applyOAuthAlias(&k.AccessToken, raw, "accessToken", "access_token")
	applyOAuthAlias(&k.RefreshToken, raw, "refreshToken", "refresh_token")
	applyOAuthAlias(&k.SessionToken, raw, "sessionToken", "session_token")
	applyOAuthAlias(&k.AccountID, raw, "accountId", "accountID", "account_id", "chatgptAccountId", "chatgpt_account_id")
	applyOAuthAlias(&k.LastRefresh, raw, "lastRefresh", "last_refresh")
	applyOAuthAlias(&k.Email, raw, "email")
	applyOAuthAlias(&k.Type, raw, "type")
	applyOAuthAlias(&k.Expired, raw, "expired", "expiresAt", "expires_at")
}

func applyOAuthAlias(target *string, raw map[string]any, keys ...string) {
	if strings.TrimSpace(*target) != "" {
		return
	}
	for _, key := range keys {
		if value := oauthString(raw, key); value != "" {
			*target = value
			return
		}
	}
}

func oauthString(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok || value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func oauthNestedMap(raw map[string]any, key string) (map[string]any, bool) {
	value, ok := raw[key]
	if !ok || value == nil {
		return nil, false
	}
	nested, ok := value.(map[string]any)
	return nested, ok
}

func ParseOAuthKey(raw string) (*OAuthKey, error) {
	if raw == "" {
		return nil, errors.New("codex channel: empty oauth key")
	}
	var key OAuthKey
	if err := common.Unmarshal([]byte(raw), &key); err != nil {
		return nil, errors.New("codex channel: invalid oauth key json")
	}
	return &key, nil
}
