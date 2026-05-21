package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
)

type CodexCredentialRefreshOptions struct {
	ResetCaches bool
}

type CodexOAuthKey struct {
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

func (k *CodexOAuthKey) UnmarshalJSON(data []byte) error {
	type codexOAuthKey CodexOAuthKey
	var canonical codexOAuthKey
	if err := common.Unmarshal(data, &canonical); err != nil {
		return err
	}

	*k = CodexOAuthKey(canonical)

	var raw map[string]any
	if err := common.Unmarshal(data, &raw); err != nil {
		return err
	}
	k.applyAliasFields(raw)
	for _, nestedKey := range []string{"openaiOauth", "openai_oauth"} {
		if nested, ok := codexOAuthNestedMap(raw, nestedKey); ok {
			k.applyAliasFields(nested)
		}
	}
	return nil
}

func (k *CodexOAuthKey) applyAliasFields(raw map[string]any) {
	applyCodexOAuthAlias(&k.IDToken, raw, "idToken", "id_token")
	applyCodexOAuthAlias(&k.AccessToken, raw, "accessToken", "access_token")
	applyCodexOAuthAlias(&k.RefreshToken, raw, "refreshToken", "refresh_token")
	applyCodexOAuthAlias(&k.SessionToken, raw, "sessionToken", "session_token")
	applyCodexOAuthAlias(&k.AccountID, raw, "accountId", "accountID", "account_id", "chatgptAccountId", "chatgpt_account_id")
	applyCodexOAuthAlias(&k.LastRefresh, raw, "lastRefresh", "last_refresh")
	applyCodexOAuthAlias(&k.Email, raw, "email")
	applyCodexOAuthAlias(&k.Type, raw, "type")
	applyCodexOAuthAlias(&k.Expired, raw, "expired", "expiresAt", "expires_at")
}

func applyCodexOAuthAlias(target *string, raw map[string]any, keys ...string) {
	if strings.TrimSpace(*target) != "" {
		return
	}
	for _, key := range keys {
		if value := codexOAuthString(raw, key); value != "" {
			*target = value
			return
		}
	}
}

func codexOAuthString(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok || value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func codexOAuthNestedMap(raw map[string]any, key string) (map[string]any, bool) {
	value, ok := raw[key]
	if !ok || value == nil {
		return nil, false
	}
	nested, ok := value.(map[string]any)
	return nested, ok
}

func parseCodexOAuthKey(raw string) (*CodexOAuthKey, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("codex channel: empty oauth key")
	}
	var key CodexOAuthKey
	if err := common.Unmarshal([]byte(raw), &key); err != nil {
		return nil, errors.New("codex channel: invalid oauth key json")
	}
	return &key, nil
}

func codexCredentialHasTokenExpiredReason(otherInfo string) bool {
	lower := strings.ToLower(otherInfo)
	return strings.Contains(lower, "token_expired") ||
		strings.Contains(lower, "authentication token is expired")
}

func RefreshCodexChannelCredential(ctx context.Context, channelID int, opts CodexCredentialRefreshOptions) (*CodexOAuthKey, *model.Channel, error) {
	ch, err := model.GetChannelById(channelID, true)
	if err != nil {
		return nil, nil, err
	}
	if ch == nil {
		return nil, nil, fmt.Errorf("channel not found")
	}
	if ch.Type != constant.ChannelTypeCodex {
		return nil, nil, fmt.Errorf("channel type is not Codex")
	}

	oauthKey, err := parseCodexOAuthKey(strings.TrimSpace(ch.Key))
	if err != nil {
		return nil, nil, err
	}

	refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	refreshToken := strings.TrimSpace(oauthKey.RefreshToken)
	sessionToken := NormalizeCodexSessionToken(oauthKey.SessionToken)
	switch {
	case refreshToken != "":
		res, err := RefreshCodexOAuthTokenWithProxy(refreshCtx, refreshToken, ch.GetSetting().Proxy)
		if err != nil {
			return nil, nil, err
		}
		oauthKey.AccessToken = res.AccessToken
		oauthKey.RefreshToken = res.RefreshToken
		oauthKey.Expired = res.ExpiresAt.Format(time.RFC3339)
	case sessionToken != "":
		res, err := RefreshCodexAccessTokenWithSessionToken(refreshCtx, sessionToken, ch.GetBaseURL(), ch.GetSetting().Proxy)
		if err != nil {
			return nil, nil, err
		}
		oauthKey.AccessToken = res.AccessToken
		oauthKey.SessionToken = sessionToken
		if !res.ExpiresAt.IsZero() {
			oauthKey.Expired = res.ExpiresAt.Format(time.RFC3339)
		}
		if strings.TrimSpace(oauthKey.Email) == "" && strings.TrimSpace(res.Email) != "" {
			oauthKey.Email = strings.TrimSpace(res.Email)
		}
	default:
		return nil, nil, fmt.Errorf("codex channel: refresh_token or session_token is required to refresh credential")
	}

	oauthKey.LastRefresh = time.Now().Format(time.RFC3339)
	if strings.TrimSpace(oauthKey.Type) == "" {
		oauthKey.Type = "codex"
	}

	if accountID, ok := ExtractCodexAccountIDFromJWT(oauthKey.AccessToken); ok {
		oauthKey.AccountID = accountID
	}
	if email, ok := ExtractEmailFromJWT(oauthKey.AccessToken); ok {
		oauthKey.Email = email
	}
	if strings.TrimSpace(oauthKey.AccountID) == "" {
		return nil, nil, fmt.Errorf("codex channel: account_id is required after refreshing credential")
	}

	encoded, err := common.Marshal(oauthKey)
	if err != nil {
		return nil, nil, err
	}

	if err := model.DB.Model(&model.Channel{}).Where("id = ?", ch.Id).Update("key", string(encoded)).Error; err != nil {
		return nil, nil, err
	}
	if ch.Status == common.ChannelStatusAutoDisabled && codexCredentialHasTokenExpiredReason(ch.OtherInfo) {
		model.UpdateChannelStatus(ch.Id, "", common.ChannelStatusEnabled, "")
	}

	if opts.ResetCaches {
		model.InitChannelCache()
		ResetProxyClientCache()
	}

	return oauthKey, ch, nil
}
