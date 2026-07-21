package profile

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- asserting the protocol-compatible identifier derivation.
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func TestComputeIOSVerifyGolden(t *testing.T) {
	t.Parallel()
	verify, err := ComputeIOSVerify(
		"f7a82870a6ba9b65a0a57a54b318ae80ca607bec",
		"20260721042157621",
		bytes.NewReader([]byte{15, 14, 22, 49}),
	)
	if err != nil {
		t.Fatal(err)
	}
	const golden = "NmE2Zjk0NDOWxMM3ODVmZjhjZjhiZjU1YjZiNDZjNTAyYTU="
	if verify != golden {
		t.Fatalf("verify = %q, want %q", verify, golden)
	}
}

func TestIOSLoginFieldsMatchCapturedProfile(t *testing.T) {
	t.Parallel()
	const installationID = "0123456789abcdef0123456789abcdef"
	fields, err := (IOS{}).BuildLoginFields(LoginInput{
		Account: "person@example.test", Password: "not-persisted", InstallationID: installationID,
	}, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	deviceDigest := sha1.Sum([]byte("kfadapter-kuaifan-device\x00" + installationID))
	deviceID := hex.EncodeToString(deviceDigest[:])
	if fields.DeviceID != deviceID || fields.OpenUDID != deviceID || fields.UUID != installationID || fields.UDID != "" || fields.IDFA != "" || fields.IMEI != "" {
		t.Fatalf("unexpected synthetic identifiers: %#v", fields)
	}
	wantVerify, err := ComputeIOSVerify(deviceID, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if fields.Verify != wantVerify || fields.LoginType != 4 || fields.MAC != DefaultSyntheticMAC || fields.UserID != "" {
		t.Fatalf("unexpected iOS login fields: %#v", fields)
	}
	if fields.OS != IOSOS || fields.Edition != IOSEdition || fields.OSVersion != IOSOSVersion || fields.DeviceType != "iPhone" || fields.ClientVersion != IOSClientVersion || fields.VirtualMachine || !fields.WithSimCard {
		t.Fatalf("unexpected iOS profile constants: %#v", fields)
	}
	if fields.Signature != fields.Certification || fields.Extra == nil || len(fields.Extra) != 0 {
		t.Fatal("invalid captured constants")
	}
	wire, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte(`"nickname":""`)) || bytes.Contains(wire, []byte(`"nickName"`)) {
		t.Fatalf("unexpected nickname wire key: %s", wire)
	}
}

func TestIOSVerifyRequiresLowercaseSHA1Shape(t *testing.T) {
	t.Parallel()
	for _, deviceID := range []string{
		"020000000000",
		"F7A82870A6BA9B65A0A57A54B318AE80CA607BEC",
		"f7a82870a6ba9b65a0a57a54b318ae80ca607beg",
		"f7a82870a6ba9b65a0a57a54b318ae80ca607be",
	} {
		if _, err := ComputeIOSVerify(deviceID, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrInvalidVerifyInput) {
			t.Fatalf("ComputeIOSVerify(%q) error = %v", deviceID, err)
		}
	}
}

func TestIOSDefinition(t *testing.T) {
	t.Parallel()
	var definition Definition = IOS{}
	if definition.ID() != IOSID || definition.UserAgent() != IOSUserAgent || !definition.RequiresPostLoginRefresh() {
		t.Fatalf("iOS definition = %#v", definition)
	}
	if eligible, err := definition.ValidateLine("WIFIIN", ""); err != nil || !eligible {
		t.Fatalf("iOS WIFIIN eligibility = %t, %v", eligible, err)
	}
}
