package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
)

const (
	GeminiOAuthAuthorizeURL        = "https://accounts.google.com/o/oauth2/v2/auth"
	GeminiOAuthTokenURL            = "https://oauth2.googleapis.com/token"
	GeminiOAuthDefaultRedirectURI  = "http://localhost:1455/oauth2callback"
	GeminiOAuthDefaultScope        = "openid email profile https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever"
	GeminiOAuthCredentialType      = "gemini_oauth"
	geminiOAuthRefreshSkew         = 5 * time.Minute
	geminiOAuthRequestTimeout      = 20 * time.Second
	geminiOAuthUserProjectHeader   = "x-goog-user-project"
	geminiOAuthAuthorizationHeader = "Authorization"
)

type GeminiOAuthAuthorizationFlow struct {
	State        string
	Verifier     string
	Challenge    string
	AuthorizeURL string
	RedirectURI  string
	Scopes       string
}

type GeminiOAuthTokenResult struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Scope        string
	ExpiresAt    time.Time
}

type GeminiOAuthKey struct {
	Type           string `json:"type,omitempty"`
	AccessToken    string `json:"access_token,omitempty"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	IDToken        string `json:"id_token,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	ClientSecret   string `json:"client_secret,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	QuotaProject   string `json:"quota_project_id,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	Email          string `json:"email,omitempty"`
	TokenURI       string `json:"token_uri,omitempty"`
	Scopes         string `json:"scopes,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	LastRefresh    string `json:"last_refresh,omitempty"`
	UniverseDomain string `json:"universe_domain,omitempty"`
}

type GeminiCredentialRefreshOptions struct {
	ResetCaches bool
}

func (k *GeminiOAuthKey) UnmarshalJSON(data []byte) error {
	type geminiOAuthKey GeminiOAuthKey
	var canonical geminiOAuthKey
	if err := common.Unmarshal(data, &canonical); err != nil {
		return err
	}

	*k = GeminiOAuthKey(canonical)

	var raw map[string]any
	if err := common.Unmarshal(data, &raw); err != nil {
		return err
	}
	k.applyAliasFields(raw)
	for _, nestedKey := range []string{"geminiOauth", "gemini_oauth", "googleOauth", "google_oauth", "oauth"} {
		if nested, ok := geminiOAuthNestedMap(raw, nestedKey); ok {
			k.applyAliasFields(nested)
		}
	}
	return nil
}

func (k *GeminiOAuthKey) applyAliasFields(raw map[string]any) {
	applyGeminiOAuthAlias(&k.Type, raw, "type")
	applyGeminiOAuthAlias(&k.AccessToken, raw, "access_token", "accessToken", "token")
	applyGeminiOAuthAlias(&k.RefreshToken, raw, "refresh_token", "refreshToken")
	applyGeminiOAuthAlias(&k.IDToken, raw, "id_token", "idToken")
	applyGeminiOAuthAlias(&k.ClientID, raw, "client_id", "clientId", "clientID")
	applyGeminiOAuthAlias(&k.ClientSecret, raw, "client_secret", "clientSecret")
	applyGeminiOAuthAlias(&k.ProjectID, raw, "project_id", "projectId", "projectID")
	applyGeminiOAuthAlias(&k.QuotaProject, raw, "quota_project_id", "quotaProjectId", "quotaProjectID")
	applyGeminiOAuthAlias(&k.AccountID, raw, "account_id", "accountId", "accountID", "sub")
	applyGeminiOAuthAlias(&k.Email, raw, "email")
	applyGeminiOAuthAlias(&k.TokenURI, raw, "token_uri", "tokenUri")
	applyGeminiOAuthAlias(&k.Scopes, raw, "scopes", "scope")
	applyGeminiOAuthAlias(&k.ExpiresAt, raw, "expires_at", "expiresAt", "expired", "expiry")
	applyGeminiOAuthAlias(&k.LastRefresh, raw, "last_refresh", "lastRefresh")
	applyGeminiOAuthAlias(&k.UniverseDomain, raw, "universe_domain", "universeDomain")
}

func applyGeminiOAuthAlias(target *string, raw map[string]any, keys ...string) {
	if strings.TrimSpace(*target) != "" {
		return
	}
	for _, key := range keys {
		if value := geminiOAuthString(raw, key); value != "" {
			*target = value
			return
		}
	}
}

func geminiOAuthString(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
}

func geminiOAuthNestedMap(raw map[string]any, key string) (map[string]any, bool) {
	value, ok := raw[key]
	if !ok || value == nil {
		return nil, false
	}
	nested, ok := value.(map[string]any)
	return nested, ok
}

func ParseGeminiOAuthKey(raw string) (*GeminiOAuthKey, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("gemini oauth channel: empty oauth key")
	}
	var key GeminiOAuthKey
	if err := common.Unmarshal([]byte(strings.TrimSpace(raw)), &key); err != nil {
		return nil, errors.New("gemini oauth channel: invalid oauth key json")
	}
	key.normalize()
	return &key, nil
}

func IsGeminiOAuthCredential(raw string) bool {
	key, err := ParseGeminiOAuthKey(raw)
	if err != nil {
		return false
	}
	return strings.TrimSpace(key.AccessToken) != "" ||
		strings.TrimSpace(key.RefreshToken) != "" ||
		strings.EqualFold(strings.TrimSpace(key.Type), GeminiOAuthCredentialType) ||
		strings.EqualFold(strings.TrimSpace(key.Type), "authorized_user")
}

func (k *GeminiOAuthKey) normalize() {
	k.Type = strings.TrimSpace(k.Type)
	k.AccessToken = strings.TrimSpace(k.AccessToken)
	k.RefreshToken = strings.TrimSpace(k.RefreshToken)
	k.IDToken = strings.TrimSpace(k.IDToken)
	k.ClientID = strings.TrimSpace(k.ClientID)
	k.ClientSecret = strings.TrimSpace(k.ClientSecret)
	k.ProjectID = strings.TrimSpace(k.ProjectID)
	k.QuotaProject = strings.TrimSpace(k.QuotaProject)
	k.AccountID = strings.TrimSpace(k.AccountID)
	k.Email = strings.TrimSpace(k.Email)
	k.TokenURI = strings.TrimSpace(k.TokenURI)
	k.Scopes = strings.TrimSpace(k.Scopes)
	k.ExpiresAt = strings.TrimSpace(k.ExpiresAt)
	k.LastRefresh = strings.TrimSpace(k.LastRefresh)
	k.UniverseDomain = strings.TrimSpace(k.UniverseDomain)

	if k.TokenURI == "" {
		k.TokenURI = GeminiOAuthTokenURL
	}
	if k.Type == "" || strings.EqualFold(k.Type, "authorized_user") {
		k.Type = GeminiOAuthCredentialType
	}
	if k.QuotaProject == "" && k.ProjectID != "" {
		k.QuotaProject = k.ProjectID
	}
	if k.ProjectID == "" && k.QuotaProject != "" {
		k.ProjectID = k.QuotaProject
	}
	if k.Scopes == "" {
		k.Scopes = GeminiOAuthDefaultScope
	}
	if k.UniverseDomain == "" {
		k.UniverseDomain = "googleapis.com"
	}
	if k.IDToken != "" {
		if accountID, ok := ExtractSubjectFromJWT(k.IDToken); ok {
			k.AccountID = accountID
		}
		if email, ok := ExtractEmailFromJWT(k.IDToken); ok {
			k.Email = email
		}
	}
}

func (k *GeminiOAuthKey) EffectiveProjectID() string {
	if strings.TrimSpace(k.ProjectID) != "" {
		return strings.TrimSpace(k.ProjectID)
	}
	return strings.TrimSpace(k.QuotaProject)
}

func (k *GeminiOAuthKey) ParsedExpiresAt() (time.Time, bool) {
	raw := strings.TrimSpace(k.ExpiresAt)
	if raw == "" {
		return time.Time{}, false
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed, true
	}
	if parsed, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", raw); err == nil {
		return parsed, true
	}
	return time.Time{}, false
}

func GeminiOAuthCredentialNeedsRefresh(key *GeminiOAuthKey, now time.Time) bool {
	if key == nil {
		return true
	}
	if strings.TrimSpace(key.AccessToken) == "" {
		return true
	}
	expiresAt, ok := key.ParsedExpiresAt()
	if !ok || expiresAt.IsZero() {
		return strings.TrimSpace(key.RefreshToken) != ""
	}
	return expiresAt.Sub(now) <= geminiOAuthRefreshSkew
}

func ValidateGeminiOAuthKey(raw string) error {
	key, err := ParseGeminiOAuthKey(raw)
	if err != nil {
		return err
	}
	if key.EffectiveProjectID() == "" {
		return errors.New("Gemini OAuth key JSON must include project_id or quota_project_id")
	}
	if key.AccessToken == "" && key.RefreshToken == "" {
		return errors.New("Gemini OAuth key JSON must include access_token or refresh_token")
	}
	if key.RefreshToken != "" && key.ClientID == "" {
		return errors.New("Gemini OAuth key JSON must include client_id when refresh_token is used")
	}
	return nil
}

func CreateGeminiOAuthAuthorizationFlow(clientID, redirectURI, scopes string) (*GeminiOAuthAuthorizationFlow, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}
	redirectURI = normalizeGeminiOAuthRedirectURI(redirectURI)
	scopes = normalizeGeminiOAuthScopes(scopes)

	state, err := createStateHex(16)
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := generatePKCEPair()
	if err != nil {
		return nil, err
	}
	authorizeURL, err := buildGeminiAuthorizeURL(clientID, redirectURI, scopes, state, challenge)
	if err != nil {
		return nil, err
	}
	return &GeminiOAuthAuthorizationFlow{
		State:        state,
		Verifier:     verifier,
		Challenge:    challenge,
		AuthorizeURL: authorizeURL,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
	}, nil
}

func ExchangeGeminiAuthorizationCodeWithProxy(ctx context.Context, code, verifier, clientID, clientSecret, redirectURI, proxyURL string) (*GeminiOAuthTokenResult, error) {
	client, err := getGeminiOAuthHTTPClient(proxyURL)
	if err != nil {
		return nil, err
	}
	return exchangeGeminiAuthorizationCode(ctx, client, code, verifier, clientID, clientSecret, redirectURI)
}

func RefreshGeminiOAuthTokenWithProxy(ctx context.Context, refreshToken, clientID, clientSecret, proxyURL string) (*GeminiOAuthTokenResult, error) {
	client, err := getGeminiOAuthHTTPClient(proxyURL)
	if err != nil {
		return nil, err
	}
	return refreshGeminiOAuthToken(ctx, client, refreshToken, clientID, clientSecret)
}

func PrepareGeminiOAuthKeyForSave(ctx context.Context, raw string, proxyURL string) (string, *GeminiOAuthKey, error) {
	key, err := ParseGeminiOAuthKey(raw)
	if err != nil {
		return "", nil, err
	}
	if key.EffectiveProjectID() == "" {
		return "", nil, errors.New("Gemini OAuth key JSON must include project_id or quota_project_id")
	}

	if GeminiOAuthCredentialNeedsRefresh(key, time.Now()) {
		if key.RefreshToken == "" {
			return "", nil, errors.New("Gemini OAuth key JSON must include refresh_token to refresh access_token")
		}
		if key.ClientID == "" {
			return "", nil, errors.New("Gemini OAuth key JSON must include client_id to refresh access_token")
		}
		refreshCtx, cancel := context.WithTimeout(ctx, geminiOAuthRequestTimeout)
		defer cancel()

		res, err := RefreshGeminiOAuthTokenWithProxy(refreshCtx, key.RefreshToken, key.ClientID, key.ClientSecret, proxyURL)
		if err != nil {
			return "", nil, fmt.Errorf("failed to refresh Gemini OAuth access_token: %w", err)
		}
		key.AccessToken = res.AccessToken
		if strings.TrimSpace(res.RefreshToken) != "" {
			key.RefreshToken = res.RefreshToken
		}
		if strings.TrimSpace(res.IDToken) != "" {
			key.IDToken = res.IDToken
		}
		key.ExpiresAt = res.ExpiresAt.Format(time.RFC3339)
		key.LastRefresh = time.Now().Format(time.RFC3339)
		if res.Scope != "" {
			key.Scopes = res.Scope
		}
	}

	key.normalize()
	encoded, err := common.Marshal(key)
	if err != nil {
		return "", nil, err
	}
	return string(encoded), key, nil
}

func ResolveGeminiOAuthKeyForRequest(ctx context.Context, channelID int, isMultiKey bool, multiKeyIndex int, raw string, proxyURL string) (*GeminiOAuthKey, error) {
	prepared, key, err := PrepareGeminiOAuthKeyForSave(ctx, raw, proxyURL)
	if err != nil {
		return nil, err
	}

	if channelID > 0 && strings.TrimSpace(prepared) != strings.TrimSpace(raw) {
		if err := persistResolvedGeminiOAuthKey(channelID, isMultiKey, multiKeyIndex, raw, prepared); err != nil {
			common.SysError(fmt.Sprintf("failed to persist refreshed Gemini OAuth credential for channel %d: %s", channelID, err.Error()))
		}
	}

	return key, nil
}

func RefreshGeminiChannelCredential(ctx context.Context, channelID int, opts GeminiCredentialRefreshOptions) (*GeminiOAuthKey, *model.Channel, error) {
	ch, err := model.GetChannelById(channelID, true)
	if err != nil {
		return nil, nil, err
	}
	if ch == nil {
		return nil, nil, errors.New("channel not found")
	}
	if ch.Type != constant.ChannelTypeGemini {
		return nil, nil, errors.New("channel type is not Gemini")
	}
	if ch.ChannelInfo.IsMultiKey {
		return nil, nil, errors.New("Gemini OAuth credential refresh does not support multi-key channels")
	}

	prepared, key, err := PrepareGeminiOAuthKeyForSave(ctx, strings.TrimSpace(ch.Key), ch.GetSetting().Proxy)
	if err != nil {
		return nil, nil, err
	}
	if err := model.DB.Model(&model.Channel{}).Where("id = ?", ch.Id).Update("key", prepared).Error; err != nil {
		return nil, nil, err
	}
	ch.Key = prepared

	if ch.Status == common.ChannelStatusAutoDisabled && geminiCredentialHasTokenExpiredReason(ch.OtherInfo) {
		model.UpdateChannelStatus(ch.Id, "", common.ChannelStatusEnabled, "")
	}
	if opts.ResetCaches {
		model.InitChannelCache()
		ResetProxyClientCache()
	}

	return key, ch, nil
}

func SetGeminiOAuthHeaders(header http.Header, key *GeminiOAuthKey) error {
	if key == nil {
		return errors.New("Gemini OAuth key is nil")
	}
	if strings.TrimSpace(key.AccessToken) == "" {
		return errors.New("Gemini OAuth access_token is required")
	}
	projectID := key.EffectiveProjectID()
	if projectID == "" {
		return errors.New("Gemini OAuth project_id or quota_project_id is required")
	}
	header.Del("x-goog-api-key")
	header.Set(geminiOAuthAuthorizationHeader, "Bearer "+strings.TrimSpace(key.AccessToken))
	header.Set(geminiOAuthUserProjectHeader, projectID)
	return nil
}

func geminiCredentialHasTokenExpiredReason(otherInfo string) bool {
	lower := strings.ToLower(otherInfo)
	return strings.Contains(lower, "token_expired") ||
		strings.Contains(lower, "expired") ||
		strings.Contains(lower, "invalid_grant") ||
		strings.Contains(lower, "invalid credentials")
}

func ExtractSubjectFromJWT(token string) (string, bool) {
	claims, ok := decodeJWTClaims(token)
	if !ok {
		return "", false
	}
	v, ok := claims["sub"]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
}

func normalizeGeminiOAuthRedirectURI(redirectURI string) string {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return GeminiOAuthDefaultRedirectURI
	}
	return redirectURI
}

func normalizeGeminiOAuthScopes(scopes string) string {
	fields := strings.Fields(scopes)
	if len(fields) == 0 {
		return GeminiOAuthDefaultScope
	}
	return strings.Join(fields, " ")
}

func buildGeminiAuthorizeURL(clientID, redirectURI, scopes, state, challenge string) (string, error) {
	u, err := url.Parse(GeminiOAuthAuthorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", strings.TrimSpace(clientID))
	q.Set("redirect_uri", normalizeGeminiOAuthRedirectURI(redirectURI))
	q.Set("scope", normalizeGeminiOAuthScopes(scopes))
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")
	q.Set("include_granted_scopes", "true")
	q.Set("code_challenge", strings.TrimSpace(challenge))
	q.Set("code_challenge_method", "S256")
	q.Set("state", strings.TrimSpace(state))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func exchangeGeminiAuthorizationCode(ctx context.Context, client *http.Client, code, verifier, clientID, clientSecret, redirectURI string) (*GeminiOAuthTokenResult, error) {
	code = strings.TrimSpace(code)
	verifier = strings.TrimSpace(verifier)
	clientID = strings.TrimSpace(clientID)
	if code == "" {
		return nil, errors.New("empty authorization code")
	}
	if verifier == "" {
		return nil, errors.New("empty code_verifier")
	}
	if clientID == "" {
		return nil, errors.New("empty client_id")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	if strings.TrimSpace(clientSecret) != "" {
		form.Set("client_secret", strings.TrimSpace(clientSecret))
	}
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", normalizeGeminiOAuthRedirectURI(redirectURI))

	return postGeminiOAuthTokenForm(ctx, client, form, "Gemini OAuth code exchange")
}

func refreshGeminiOAuthToken(ctx context.Context, client *http.Client, refreshToken, clientID, clientSecret string) (*GeminiOAuthTokenResult, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	clientID = strings.TrimSpace(clientID)
	if refreshToken == "" {
		return nil, errors.New("empty refresh_token")
	}
	if clientID == "" {
		return nil, errors.New("empty client_id")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	if strings.TrimSpace(clientSecret) != "" {
		form.Set("client_secret", strings.TrimSpace(clientSecret))
	}

	return postGeminiOAuthTokenForm(ctx, client, form, "Gemini OAuth refresh")
}

func postGeminiOAuthTokenForm(ctx context.Context, client *http.Client, form url.Values, operation string) (*GeminiOAuthTokenResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, GeminiOAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := common.DecodeJson(resp.Body, &payload); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if payload.Error != "" || payload.ErrorDesc != "" {
			return nil, fmt.Errorf("%s failed: status=%d error=%s description=%s", operation, resp.StatusCode, payload.Error, payload.ErrorDesc)
		}
		return nil, fmt.Errorf("%s failed: status=%d", operation, resp.StatusCode)
	}
	if strings.TrimSpace(payload.AccessToken) == "" || payload.ExpiresIn <= 0 {
		return nil, fmt.Errorf("%s response missing access_token or expires_in", operation)
	}

	return &GeminiOAuthTokenResult{
		AccessToken:  strings.TrimSpace(payload.AccessToken),
		RefreshToken: strings.TrimSpace(payload.RefreshToken),
		IDToken:      strings.TrimSpace(payload.IDToken),
		TokenType:    strings.TrimSpace(payload.TokenType),
		Scope:        strings.TrimSpace(payload.Scope),
		ExpiresAt:    time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second),
	}, nil
}

func getGeminiOAuthHTTPClient(proxyURL string) (*http.Client, error) {
	baseClient, err := GetHttpClientWithProxy(strings.TrimSpace(proxyURL))
	if err != nil {
		return nil, err
	}
	if baseClient == nil {
		return &http.Client{Timeout: geminiOAuthRequestTimeout}, nil
	}
	clientCopy := *baseClient
	clientCopy.Timeout = geminiOAuthRequestTimeout
	return &clientCopy, nil
}

func persistResolvedGeminiOAuthKey(channelID int, isMultiKey bool, multiKeyIndex int, oldRaw string, newRaw string) error {
	ch, err := model.GetChannelById(channelID, true)
	if err != nil {
		return err
	}
	if ch == nil {
		return errors.New("channel not found")
	}

	if isMultiKey || ch.ChannelInfo.IsMultiKey {
		keys := ch.GetKeys()
		if len(keys) == 0 {
			return errors.New("channel has no keys")
		}
		replaced := false
		if multiKeyIndex >= 0 && multiKeyIndex < len(keys) && strings.TrimSpace(keys[multiKeyIndex]) == strings.TrimSpace(oldRaw) {
			keys[multiKeyIndex] = newRaw
			replaced = true
		}
		if !replaced {
			for i, key := range keys {
				if strings.TrimSpace(key) == strings.TrimSpace(oldRaw) {
					keys[i] = newRaw
					replaced = true
					break
				}
			}
		}
		if !replaced {
			return errors.New("selected key not found")
		}
		ch.Key = strings.Join(keys, "\n")
	} else {
		ch.Key = newRaw
	}

	if err := model.DB.Model(&model.Channel{}).Where("id = ?", ch.Id).Update("key", ch.Key).Error; err != nil {
		return err
	}
	model.InitChannelCache()
	return nil
}
