package control

import (
	"crypto/md5" // #nosec G501 -- legacy API compatibility algorithm specified by the protocol.
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	defaultMAC     = "020000000000"
)

var ErrInvalidVerifyInput = errors.New("control: invalid verify input")

// DefaultSyntheticMAC is a locally administered, documented fallback value.
// It never reflects a host hardware identifier.
const DefaultSyntheticMAC = defaultMAC

func validSyntheticMAC(mac string) bool {
	if len(mac) != 12 {
		return false
	}
	for _, value := range mac {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}

// ComputeVerify implements the observed login verify algorithm. randomness is
// injectable for deterministic fixtures and must be cryptographically random
// in normal use.
func ComputeVerify(mac, timestamp string, randomness io.Reader) (string, error) {
	if randomness == nil {
		randomness = rand.Reader
	}
	if len(timestamp) < 4 || !withinLimit(timestamp, maxControlFieldBytes) || !validSyntheticMAC(mac) {
		return "", ErrInvalidVerifyInput
	}
	for _, digit := range timestamp[len(timestamp)-4:] {
		if digit < '0' || digit > '9' {
			return "", ErrInvalidVerifyInput
		}
	}
	s := mac + timestamp
	half := len(s) / 2
	if half == 0 {
		return "", ErrInvalidVerifyInput
	}
	r, err := boundedRandom(randomness, half)
	if err != nil {
		return "", fmt.Errorf("control: generate verify split: %w", err)
	}
	p := half + r
	if r%2 == 1 {
		p = half - r
	}
	if p <= 0 || p >= len(s) {
		return "", ErrInvalidVerifyInput
	}
	left, right := s[:p], s[p:]
	if len(left) == 0 || len(right) == 0 || p > len(base64Alphabet) {
		return "", ErrInvalidVerifyInput
	}
	digits := [4]int{}
	for i, digit := range timestamp[len(timestamp)-4:] {
		digits[i] = int(digit - '0')
	}
	q := s + string([]byte{
		left[digits[0]%len(left)],
		left[len(left)-1-(digits[1]%len(left))],
		right[digits[2]%len(right)],
		right[len(right)-1-(digits[3]%len(right))],
	})
	digest := md5.Sum([]byte(q))
	hexDigest := make([]byte, hex.EncodedLen(len(digest)))
	hex.Encode(hexDigest, digest[:])
	e := base64.StdEncoding.EncodeToString(hexDigest)
	if len(e) < 10 {
		return "", ErrInvalidVerifyInput
	}
	randomChars := make([]byte, 3)
	for i := range randomChars {
		var b [1]byte
		if _, err := io.ReadFull(randomness, b[:]); err != nil {
			return "", fmt.Errorf("control: generate verify characters: %w", err)
		}
		randomChars[i] = base64Alphabet[int(b[0])&63]
	}
	return e[:10] + string(randomChars) + string(base64Alphabet[p-1]) + e[10:], nil
}

// LoginFields contains exactly the observed email/password login schema. The
// password exists only while this value is being encoded into an HTTPS request.
type LoginFields struct {
	Time              string         `json:"time"`
	Account           string         `json:"account"`
	Password          string         `json:"password"`
	LoginType         int            `json:"loginType"`
	NickName          string         `json:"nickName"`
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
}

// EmailLogin builds the only currently supported login wire schema. It never
// reads a host UUID, a physical MAC address, or another hardware identifier.
type EmailLogin struct {
	Account        string
	Password       string
	InstallationID string
	MAC            string
	OSVersion      string
}

// BuildEmailLoginFields returns the exact observed fields for loginType 4.
func BuildEmailLoginFields(in EmailLogin, timestamp string, randomness io.Reader) (LoginFields, error) {
	if !withinLimit(in.Account, maxControlFieldBytes) || !withinLimit(in.Password, maxControlFieldBytes) || !withinLimit(in.InstallationID, maxControlFieldBytes) || !withinLimit(in.MAC, maxControlFieldBytes) || !withinLimit(in.OSVersion, maxControlFieldBytes) || strings.TrimSpace(in.Account) == "" || in.Password == "" || strings.TrimSpace(in.InstallationID) == "" {
		return LoginFields{}, ErrInvalidVerifyInput
	}
	mac := in.MAC
	if mac == "" {
		mac = DefaultSyntheticMAC
	}
	if !validSyntheticMAC(mac) {
		return LoginFields{}, ErrInvalidVerifyInput
	}
	verify, err := ComputeVerify(mac, timestamp, randomness)
	if err != nil {
		return LoginFields{}, err
	}
	signatureDigest := md5.Sum([]byte("cc.fancast.major")) // #nosec G401 -- protocol compatibility.
	signature := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(signatureDigest[:])))
	return LoginFields{
		Time:              timestamp,
		Account:           in.Account,
		Password:          in.Password,
		LoginType:         4,
		NickName:          "",
		DeviceID:          in.InstallationID,
		UDID:              in.InstallationID,
		OpenUDID:          in.InstallationID,
		UUID:              in.InstallationID,
		IDFA:              in.InstallationID,
		MAC:               mac,
		IMEI:              "",
		UserID:            "",
		OS:                "MAC",
		Edition:           "MINOR",
		OSVersion:         in.OSVersion,
		Manufacture:       "Apple Inc",
		DeviceType:        "mac",
		ClientVersion:     "3.3.1",
		PromoPlatformCode: "AppStore",
		Verify:            verify,
		Signature:         signature,
		Certification:     signature,
		PackageName:       "cc.fancast.major",
		Extra:             map[string]any{},
	}, nil
}

func boundedRandom(reader io.Reader, n int) (int, error) {
	if n <= 0 {
		return 0, ErrInvalidVerifyInput
	}
	// Rejection sampling avoids modulo skew. The one-byte path is important
	// for the verify algorithm; nonce and backoff bounds need a uint32 sample.
	if n <= 256 {
		limit := 256 - 256%n
		for {
			var b [1]byte
			if _, err := io.ReadFull(reader, b[:]); err != nil {
				return 0, err
			}
			if int(b[0]) < limit {
				return int(b[0]) % n, nil
			}
		}
	}
	const sampleSpace = uint64(1) << 32
	limit := sampleSpace - sampleSpace%uint64(n)
	for {
		var b [4]byte
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return 0, err
		}
		value := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		if value < limit {
			return int(value % uint64(n)), nil
		}
	}
}
