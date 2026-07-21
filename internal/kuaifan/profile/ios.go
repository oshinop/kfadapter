package profile

import (
	"crypto/md5"  // #nosec G501 -- protocol compatibility.
	"crypto/sha1" // #nosec G505 -- protocol-compatible pseudonymous identifier shape.
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
)

const (
	IOSUserAgent       = "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A403 Safari/8536.25 SPEEDIN"
	IOSOS              = "IOS"
	IOSEdition         = "THIRD"
	IOSOSVersion       = "27.0"
	IOSClientVersion   = "4.18.4"
	IOSPackageName     = "cc.fancast.major"
	IOSPromoPlatform   = "AppStore"
	IOSProviderDevice  = "MAC"
	IOSProviderVersion = "1.0.46"
)

// IOS is the captured iOS 4.18.4 wire profile.
type IOS struct{}

func (IOS) ID() ID                         { return IOSID }
func (IOS) UserAgent() string              { return IOSUserAgent }
func (IOS) ConfigFields() any              { return map[string]any{"os": IOSOS} }
func (IOS) RequiresPostLoginRefresh() bool { return true }
func (IOS) ValidateLine(provider, _ string) (bool, error) {
	if provider != "WIFIIN" {
		return false, ErrInvalidLine
	}
	return true, nil
}

// IOSLoginFields is exactly the captured iOS email/password request schema.
type IOSLoginFields struct {
	Time              string         `json:"time"`
	Account           string         `json:"account"`
	Password          string         `json:"password"`
	LoginType         int            `json:"loginType"`
	Nickname          string         `json:"nickname"`
	DeviceID          string         `json:"deviceId"`
	UDID              string         `json:"udid"`
	OpenUDID          string         `json:"openUdid"`
	UUID              string         `json:"uuid"`
	IDFA              string         `json:"idfa"`
	MAC               string         `json:"mac"`
	IMEI              string         `json:"imei"`
	UserID            string         `json:"userId"`
	OS                string         `json:"os"`
	Edition           string         `json:"edition"`
	OSVersion         string         `json:"osVersion"`
	Manufacture       string         `json:"manufacture"`
	DeviceType        string         `json:"deviceType"`
	ClientVersion     string         `json:"clientVersion"`
	PromoPlatformCode string         `json:"promoPlatformCode"`
	Verify            string         `json:"verify"`
	Signature         string         `json:"signature"`
	Certification     string         `json:"certification"`
	PackageName       string         `json:"packagename"`
	Extra             map[string]any `json:"extra"`
	VirtualMachine    bool           `json:"virtualMachine"`
	WithSimCard       bool           `json:"withSimCard"`
}

// ClearPassword drops the transient request-field reference after encoding.
func (fields *IOSLoginFields) ClearPassword() {
	if fields != nil {
		fields.Password = ""
	}
}

// ComputeIOSVerify implements the captured iOS login verifier over its
// pseudonymous device identifier and request timestamp.
func ComputeIOSVerify(deviceID, timestamp string, randomness io.Reader) (string, error) {
	return computeVerify(deviceID, timestamp, randomness, validIOSDeviceID)
}

// BuildLoginFields builds the iOS login request without reading host hardware.
func (IOS) BuildLoginFields(input LoginInput, timestamp string, randomness io.Reader) (*IOSLoginFields, error) {
	if !withinLimit(input.Account) || !withinLimit(input.Password) || !withinLimit(input.InstallationID) || strings.TrimSpace(input.Account) == "" || input.Password == "" || strings.TrimSpace(input.InstallationID) == "" {
		return nil, ErrInvalidVerifyInput
	}
	deviceDigest := sha1.Sum([]byte("kfadapter-kuaifan-device\x00" + input.InstallationID))
	deviceID := hex.EncodeToString(deviceDigest[:])
	verify, err := ComputeIOSVerify(deviceID, timestamp, randomness)
	if err != nil {
		return nil, err
	}
	signatureDigest := md5.Sum([]byte(IOSPackageName)) // #nosec G401 -- protocol compatibility.
	signature := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(signatureDigest[:])))
	return &IOSLoginFields{
		Time: timestamp, Account: input.Account, Password: input.Password, LoginType: 4,
		DeviceID: deviceID, OpenUDID: deviceID, UUID: input.InstallationID,
		MAC: DefaultSyntheticMAC, OS: IOSOS, Edition: IOSEdition, OSVersion: IOSOSVersion,
		Manufacture: "Apple Inc", DeviceType: "iPhone", ClientVersion: IOSClientVersion,
		PromoPlatformCode: IOSPromoPlatform, Verify: verify, Signature: signature,
		Certification: signature, PackageName: IOSPackageName, Extra: map[string]any{},
		WithSimCard: true,
	}, nil
}

func validIOSDeviceID(deviceID string) bool {
	if len(deviceID) != sha1.Size*2 {
		return false
	}
	for _, value := range deviceID {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}
