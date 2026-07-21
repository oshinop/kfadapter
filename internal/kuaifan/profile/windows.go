package profile

import (
	"encoding/hex"
	"io"
	"strings"
)

const (
	WindowsUserAgent      = "SPEEDIN"
	WindowsOS             = "WINDOWS"
	WindowsEdition        = "MAJOR"
	WindowsOSVersion      = "10.0"
	WindowsClientVersion  = "4.3.30"
	WindowsPackageName    = "speedin"
	WindowsPromoPlatform  = "speedin.cc"
	WindowsDeviceType     = "WINDOWS"
	WindowsFixedNonce     = "07531556"
	WindowsTunnelPassword = "wifiin1234"
	WindowsTunnelMethod   = "aes-256-cfb"
)

// Windows is the recovered Windows 4.3.30 wire profile.
type Windows struct{}

func (Windows) ID() ID                         { return WindowsID }
func (Windows) UserAgent() string              { return WindowsUserAgent }
func (Windows) ConfigFields() any              { return map[string]any{"os": WindowsOS} }
func (Windows) RequiresPostLoginRefresh() bool { return false }
func (Windows) ValidateLine(provider, password string) (bool, error) {
	switch provider {
	case "WIFIIN":
		if password != WindowsTunnelPassword {
			return false, ErrInvalidLine
		}
		return true, nil
	case "WS":
		return false, nil
	default:
		return false, ErrInvalidLine
	}
}

// WindowsLoginFields is exactly the recovered Windows email/password schema.
type WindowsLoginFields struct {
	OpenID            *string `json:"openId"`
	Account           string  `json:"account"`
	LoginType         int     `json:"loginType"`
	Password          string  `json:"password"`
	DeviceID          string  `json:"deviceId"`
	MAC               string  `json:"mac"`
	IMEI              string  `json:"imei"`
	UDID              string  `json:"udid"`
	OpenUDID          string  `json:"openUdid"`
	UUID              string  `json:"uuid"`
	IDFA              string  `json:"idfa"`
	OS                string  `json:"os"`
	OSVersion         string  `json:"osVersion"`
	DeviceType        string  `json:"deviceType"`
	ClientVersion     string  `json:"clientVersion"`
	PromoPlatformCode string  `json:"promoPlatformCode"`
	Time              string  `json:"time"`
	Verify            string  `json:"verify"`
	Signature         string  `json:"signature"`
	Certification     string  `json:"certification"`
	PackageName       string  `json:"packageName"`
	Lang              string  `json:"lang"`
	SDKPartnerKey     string  `json:"sdkPartnerKey"`
	SDKPartnerUserID  string  `json:"sdkPartnerUserId"`
	Edition           string  `json:"edition"`
	Nonce             string  `json:"nonce"`
	UserID            *int32  `json:"userId"`
}

// ClearPassword drops the transient request-field reference after encoding.
func (fields *WindowsLoginFields) ClearPassword() {
	if fields != nil {
		fields.Password = ""
	}
}

// ComputeWindowsVerify implements the recovered Windows login verifier over
// the synthetic MAC and request timestamp.
func ComputeWindowsVerify(mac, timestamp string, randomness io.Reader) (string, error) {
	return computeVerify(mac, timestamp, randomness, validWindowsMAC)
}

// BuildLoginFields builds the Windows request from protected random
// installation state rather than host hardware identifiers.
func (Windows) BuildLoginFields(input LoginInput, timestamp, language string, randomness io.Reader) (*WindowsLoginFields, error) {
	if !withinLimit(input.Account) || !withinLimit(input.Password) || !withinLimit(language) || strings.TrimSpace(input.Account) == "" || input.Password == "" || strings.TrimSpace(language) == "" {
		return nil, ErrInvalidVerifyInput
	}
	deviceID, err := windowsDeviceGUID(input.InstallationID)
	if err != nil {
		return nil, err
	}
	verify, err := ComputeWindowsVerify(DefaultSyntheticMAC, timestamp, randomness)
	if err != nil {
		return nil, err
	}
	return &WindowsLoginFields{
		Account: input.Account, LoginType: 4, Password: input.Password, DeviceID: deviceID,
		MAC: DefaultSyntheticMAC, UDID: deviceID, OpenUDID: deviceID, UUID: deviceID, IDFA: deviceID,
		OS: WindowsOS, OSVersion: WindowsOSVersion, DeviceType: WindowsDeviceType,
		ClientVersion: WindowsClientVersion, PromoPlatformCode: WindowsPromoPlatform,
		Time: timestamp, Verify: verify, PackageName: WindowsPackageName, Lang: language,
		Edition: WindowsEdition, Nonce: WindowsFixedNonce,
	}, nil
}

func windowsDeviceGUID(installationID string) (string, error) {
	raw, err := hex.DecodeString(installationID)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != installationID {
		return "", ErrInvalidVerifyInput
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func validWindowsMAC(mac string) bool {
	if len(mac) != 12 {
		return false
	}
	for _, value := range mac {
		if !(value >= '0' && value <= '9' || value >= 'A' && value <= 'F') {
			return false
		}
	}
	return true
}
