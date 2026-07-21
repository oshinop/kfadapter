package kuaifan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"github.com/kfadapter/kfadapter/internal/kuaifan/wifiin"
	"github.com/kfadapter/kfadapter/internal/state"
)

type windowsClientProfile struct{ wire wireprofile.Windows }

func (p windowsClientProfile) id() state.ClientProfile { return state.ClientProfileWindows }
func (p windowsClientProfile) userAgent() string       { return p.wire.UserAgent() }
func (p windowsClientProfile) configFields() any       { return p.wire.ConfigFields() }
func (p windowsClientProfile) requiresPostLoginRefresh() bool {
	return p.wire.RequiresPostLoginRefresh()
}

func (p windowsClientProfile) login(ctx context.Context, c *Client, base *url.URL, input EmailLogin) (LoginSession, error) {
	fields, err := p.wire.BuildLoginFields(wireprofile.LoginInput{
		Account: input.Account, Password: input.Password, InstallationID: input.InstallationID,
	}, c.timestamp(), c.language, c.random)
	if err != nil {
		return LoginSession{}, err
	}
	response, err := c.post(ctx, base, "/v4/user/login.do", fields)
	fields.ClearPassword()
	if err != nil {
		return LoginSession{}, err
	}
	if *response.Status != 1 && *response.Status != 119 {
		return LoginSession{}, fmt.Errorf("%w: %d", ErrLoginRejected, *response.Status)
	}
	return windowsSessionFromFields(response.Fields, base)
}

func (windowsClientProfile) refresh(ctx context.Context, c *Client, session LoginSession) (LoginSession, error) {
	if err := c.validateSession(session); err != nil {
		return LoginSession{}, err
	}
	nonce, err := c.requestNonce()
	if err != nil {
		return LoginSession{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/user/refresh.do", map[string]any{
		"userId": formatUserID(session.UserID), "token": session.Token,
		"lang": c.language, "time": c.timestamp(), "nonce": nonce,
	})
	if err != nil {
		return LoginSession{}, err
	}
	if *response.Status != 1 && *response.Status != 119 {
		return LoginSession{}, businessStatus(*response.Status)
	}
	updated, err := windowsSessionFromFields(response.Fields, session.APIBase)
	if err != nil || updated.UserID != session.UserID {
		return LoginSession{}, ErrSchema
	}
	return updated, nil
}

func windowsSessionFromFields(fields map[string]json.RawMessage, base *url.URL) (LoginSession, error) {
	token, err := requiredString(fields, "token")
	if err != nil {
		return LoginSession{}, err
	}
	userID, err := requiredPositiveInt32(fields, "userId")
	if err != nil {
		return LoginSession{}, err
	}
	isVIP, err := requiredBool(fields, "isVip")
	if err != nil {
		return LoginSession{}, err
	}
	vipEndsAt, err := requiredUnixMilli(fields, "vipEndTime")
	if err != nil || isVIP && vipEndsAt.IsZero() {
		return LoginSession{}, ErrSchema
	}
	return LoginSession{
		UserID: userID, Token: token, APIBase: cloneURL(base),
		Profile: AccountProfile{IsVIP: isVIP, VIPEndsAt: vipEndsAt},
	}, nil
}

func (windowsClientProfile) fetchAuthority(ctx context.Context, c *Client, session LoginSession) (Authority, error) {
	if err := c.validateSession(session); err != nil {
		return Authority{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/invpn/getAuthority.do", map[string]any{
		"userId": session.UserID, "token": session.Token, "lang": c.language,
		"time": c.timestamp(), "nonce": wireprofile.WindowsFixedNonce,
	})
	if err != nil {
		return Authority{}, err
	}
	if *response.Status != 1 {
		return Authority{}, businessStatus(*response.Status)
	}
	providerToken, err := requiredString(response.Fields, "token")
	if err != nil {
		return Authority{}, err
	}
	orderID, err := requiredString(response.Fields, "cpOrderNo")
	if err != nil {
		return Authority{}, err
	}
	userIDText := formatUserID(session.UserID)
	providerExtension, err := wifiin.ProviderExtensionForProfile(string(state.ClientProfileWindows), providerToken, orderID, userIDText)
	if err != nil {
		return Authority{}, ErrSchema
	}
	return Authority{
		UserID: userIDText, OrderID: orderID, EncryptKey: wireprofile.WindowsTunnelPassword,
		EncryptType: wireprofile.WindowsTunnelMethod, ProviderToken: providerToken, ProviderExtension: providerExtension,
	}, nil
}

func (windowsClientProfile) fetchLines(ctx context.Context, c *Client, session LoginSession) (Lines, error) {
	if err := c.validateSession(session); err != nil {
		return Lines{}, err
	}
	nonce, err := c.requestNonce()
	if err != nil {
		return Lines{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/invpn/getLines.do", map[string]any{
		"userId": session.UserID, "token": session.Token, "os": wireprofile.WindowsOS,
		"time": c.timestamp(), "clientVersion": wireprofile.WindowsClientVersion,
		"edition": wireprofile.WindowsEdition, "lang": c.language, "nonce": nonce,
	})
	if err != nil {
		return Lines{}, err
	}
	if *response.Status != 1 {
		return Lines{}, businessStatus(*response.Status)
	}
	return validateLinesForProfile(response.Fields, c.language, windowsClientProfile{})
}

func (p windowsClientProfile) validateLine(object map[string]json.RawMessage, provider string) (bool, error) {
	password := ""
	if provider == "WIFIIN" {
		var err error
		password, err = requiredString(object, "password")
		if err != nil {
			return false, ErrInvalidLine
		}
	}
	eligible, err := p.wire.ValidateLine(provider, password)
	if err != nil {
		return false, ErrInvalidLine
	}
	return eligible, nil
}

func (c *Client) requestNonce() (string, error) {
	value, err := wireprofile.RandomInt(c.random, 90000000)
	if err != nil {
		return "", fmt.Errorf("control: nonce: %w", err)
	}
	return strconv.Itoa(10000000 + value), nil
}
