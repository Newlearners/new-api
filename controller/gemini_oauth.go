package controller

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type geminiOAuthStartRequest struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Scopes      string `json:"scopes"`
}

type geminiOAuthCompleteRequest struct {
	Input        string `json:"input"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ProjectID    string `json:"project_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scopes       string `json:"scopes"`
}

func geminiOAuthSessionKey(channelID int, field string) string {
	return fmt.Sprintf("gemini_oauth_%s_%d", field, channelID)
}

func StartGeminiOAuth(c *gin.Context) {
	startGeminiOAuthWithChannelID(c, 0)
}

func StartGeminiOAuthForChannel(c *gin.Context) {
	channelID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiError(c, fmt.Errorf("invalid channel id: %w", err))
		return
	}
	startGeminiOAuthWithChannelID(c, channelID)
}

func startGeminiOAuthWithChannelID(c *gin.Context, channelID int) {
	if channelID > 0 {
		ch, err := model.GetChannelById(channelID, false)
		if err != nil {
			common.ApiError(c, err)
			return
		}
		if ch == nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "channel not found"})
			return
		}
		if ch.Type != constant.ChannelTypeGemini {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "channel type is not Gemini"})
			return
		}
	}

	req := geminiOAuthStartRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiError(c, err)
		return
	}

	flow, err := service.CreateGeminiOAuthAuthorizationFlow(req.ClientID, req.RedirectURI, req.Scopes)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	session := sessions.Default(c)
	session.Set(geminiOAuthSessionKey(channelID, "state"), flow.State)
	session.Set(geminiOAuthSessionKey(channelID, "verifier"), flow.Verifier)
	session.Set(geminiOAuthSessionKey(channelID, "client_id"), strings.TrimSpace(req.ClientID))
	session.Set(geminiOAuthSessionKey(channelID, "redirect_uri"), flow.RedirectURI)
	session.Set(geminiOAuthSessionKey(channelID, "scopes"), flow.Scopes)
	session.Set(geminiOAuthSessionKey(channelID, "created_at"), time.Now().Unix())
	_ = session.Save()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"authorize_url": flow.AuthorizeURL,
			"redirect_uri":  flow.RedirectURI,
			"scopes":        flow.Scopes,
		},
	})
}

func CompleteGeminiOAuth(c *gin.Context) {
	completeGeminiOAuthWithChannelID(c, 0)
}

func CompleteGeminiOAuthForChannel(c *gin.Context) {
	channelID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiError(c, fmt.Errorf("invalid channel id: %w", err))
		return
	}
	completeGeminiOAuthWithChannelID(c, channelID)
}

func completeGeminiOAuthWithChannelID(c *gin.Context, channelID int) {
	req := geminiOAuthCompleteRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiError(c, err)
		return
	}

	code, state, err := parseCodexAuthorizationInput(req.Input)
	if err != nil {
		common.SysError("failed to parse gemini authorization input: " + err.Error())
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "解析授权信息失败，请检查输入格式"})
		return
	}
	if strings.TrimSpace(code) == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "missing authorization code"})
		return
	}
	if strings.TrimSpace(state) == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "missing state in input"})
		return
	}

	channelProxy := ""
	var channel *model.Channel
	if channelID > 0 {
		ch, err := model.GetChannelById(channelID, false)
		if err != nil {
			common.ApiError(c, err)
			return
		}
		if ch == nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "channel not found"})
			return
		}
		if ch.Type != constant.ChannelTypeGemini {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "channel type is not Gemini"})
			return
		}
		channel = ch
		channelProxy = ch.GetSetting().Proxy
	}

	session := sessions.Default(c)
	expectedState, _ := session.Get(geminiOAuthSessionKey(channelID, "state")).(string)
	verifier, _ := session.Get(geminiOAuthSessionKey(channelID, "verifier")).(string)
	sessionClientID, _ := session.Get(geminiOAuthSessionKey(channelID, "client_id")).(string)
	sessionRedirectURI, _ := session.Get(geminiOAuthSessionKey(channelID, "redirect_uri")).(string)
	sessionScopes, _ := session.Get(geminiOAuthSessionKey(channelID, "scopes")).(string)
	if strings.TrimSpace(expectedState) == "" || strings.TrimSpace(verifier) == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "oauth flow not started or session expired"})
		return
	}
	if state != expectedState {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "state mismatch"})
		return
	}

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = strings.TrimSpace(sessionClientID)
	}
	if clientID == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "client_id is required"})
		return
	}
	if strings.TrimSpace(sessionClientID) != "" && clientID != strings.TrimSpace(sessionClientID) {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "client_id mismatch"})
		return
	}

	redirectURI := strings.TrimSpace(req.RedirectURI)
	if redirectURI == "" {
		redirectURI = strings.TrimSpace(sessionRedirectURI)
	}
	if redirectURI == "" {
		redirectURI = service.GeminiOAuthDefaultRedirectURI
	}
	if strings.TrimSpace(sessionRedirectURI) != "" && redirectURI != strings.TrimSpace(sessionRedirectURI) {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "redirect_uri mismatch"})
		return
	}

	projectID := strings.TrimSpace(req.ProjectID)
	if projectID == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "project_id is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	tokenRes, err := service.ExchangeGeminiAuthorizationCodeWithProxy(ctx, code, verifier, clientID, req.ClientSecret, redirectURI, channelProxy)
	if err != nil {
		common.SysError("failed to exchange gemini authorization code: " + err.Error())
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "授权码交换失败，请重试"})
		return
	}
	if strings.TrimSpace(tokenRes.RefreshToken) == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "授权响应缺少 refresh_token，请重新授权并确认已同意离线访问"})
		return
	}

	email, _ := service.ExtractEmailFromJWT(tokenRes.IDToken)
	accountID, _ := service.ExtractSubjectFromJWT(tokenRes.IDToken)
	scopes := strings.TrimSpace(req.Scopes)
	if scopes == "" {
		scopes = strings.TrimSpace(sessionScopes)
	}
	if scopes == "" {
		scopes = strings.TrimSpace(tokenRes.Scope)
	}
	if scopes == "" {
		scopes = service.GeminiOAuthDefaultScope
	}

	key := service.GeminiOAuthKey{
		Type:         service.GeminiOAuthCredentialType,
		AccessToken:  tokenRes.AccessToken,
		RefreshToken: tokenRes.RefreshToken,
		IDToken:      tokenRes.IDToken,
		ClientID:     clientID,
		ClientSecret: strings.TrimSpace(req.ClientSecret),
		ProjectID:    projectID,
		QuotaProject: projectID,
		AccountID:    accountID,
		Email:        email,
		TokenURI:     service.GeminiOAuthTokenURL,
		Scopes:       scopes,
		ExpiresAt:    tokenRes.ExpiresAt.Format(time.RFC3339),
		LastRefresh:  time.Now().Format(time.RFC3339),
	}
	encoded, err := common.Marshal(key)
	if err != nil {
		common.ApiError(c, err)
		return
	}

	session.Delete(geminiOAuthSessionKey(channelID, "state"))
	session.Delete(geminiOAuthSessionKey(channelID, "verifier"))
	session.Delete(geminiOAuthSessionKey(channelID, "client_id"))
	session.Delete(geminiOAuthSessionKey(channelID, "redirect_uri"))
	session.Delete(geminiOAuthSessionKey(channelID, "scopes"))
	session.Delete(geminiOAuthSessionKey(channelID, "created_at"))
	_ = session.Save()

	if channelID > 0 {
		settings := channel.GetOtherSettings()
		settings.GeminiKeyType = dto.GeminiKeyTypeOAuth
		channel.SetOtherSettings(settings)
		updates := map[string]any{
			"key":      string(encoded),
			"settings": channel.OtherSettings,
		}
		if err := model.DB.Model(&model.Channel{}).Where("id = ?", channelID).Updates(updates).Error; err != nil {
			common.ApiError(c, err)
			return
		}
		model.InitChannelCache()
		service.ResetProxyClientCache()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "saved",
			"data": gin.H{
				"channel_id":   channelID,
				"account_id":   accountID,
				"email":        email,
				"project_id":   projectID,
				"expires_at":   key.ExpiresAt,
				"last_refresh": key.LastRefresh,
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "generated",
		"data": gin.H{
			"key":          string(encoded),
			"account_id":   accountID,
			"email":        email,
			"project_id":   projectID,
			"expires_at":   key.ExpiresAt,
			"last_refresh": key.LastRefresh,
		},
	})
}

func RefreshGeminiChannelCredential(c *gin.Context) {
	channelID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiError(c, fmt.Errorf("invalid channel id: %w", err))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	oauthKey, ch, err := service.RefreshGeminiChannelCredential(ctx, channelID, service.GeminiCredentialRefreshOptions{ResetCaches: true})
	if err != nil {
		common.SysError("failed to refresh gemini channel credential: " + err.Error())
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "刷新凭证失败，请稍后重试"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "refreshed",
		"data": gin.H{
			"expires_at":   oauthKey.ExpiresAt,
			"last_refresh": oauthKey.LastRefresh,
			"account_id":   oauthKey.AccountID,
			"email":        oauthKey.Email,
			"project_id":   oauthKey.EffectiveProjectID(),
			"channel_id":   ch.Id,
			"channel_type": ch.Type,
			"channel_name": ch.Name,
		},
	})
}
