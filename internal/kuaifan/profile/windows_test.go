package profile

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestComputeWindowsVerifyGolden(t *testing.T) {
	t.Parallel()
	verify, err := ComputeWindowsVerify(
		"020000000000",
		"20260721042157621",
		bytes.NewReader([]byte{15, 14, 22, 49}),
	)
	if err != nil {
		t.Fatal(err)
	}
	const golden = "MjQzYTgyYzOWxMViNzk3NmE1NGVkMWUwNGExNzg4ZWMyOTY="
	if verify != golden {
		t.Fatalf("verify = %q, want %q", verify, golden)
	}
}

func TestWindowsLoginFieldsMatchRecoveredProfile(t *testing.T) {
	t.Parallel()
	const installationID = "0123456789abcdef0123456789abcdef"
	const deviceID = "01234567-89ab-4def-8123-456789abcdef"
	fields, err := (Windows{}).BuildLoginFields(LoginInput{
		Account: "person@example.test", Password: "not-persisted", InstallationID: installationID,
	}, "20260715101112123", "zh-CN", bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if fields.DeviceID != deviceID || fields.UDID != deviceID || fields.OpenUDID != deviceID || fields.UUID != deviceID || fields.IDFA != deviceID || fields.IMEI != "" {
		t.Fatalf("unexpected synthetic identifiers: %#v", fields)
	}
	wantVerify, err := ComputeWindowsVerify(DefaultSyntheticMAC, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if fields.Verify != wantVerify || fields.LoginType != 4 || fields.MAC != DefaultSyntheticMAC || fields.OpenID != nil || fields.UserID != nil {
		t.Fatalf("unexpected Windows login fields: %#v", fields)
	}
	if fields.OS != WindowsOS || fields.Edition != WindowsEdition || fields.OSVersion != WindowsOSVersion || fields.DeviceType != WindowsDeviceType || fields.ClientVersion != WindowsClientVersion || fields.PackageName != WindowsPackageName || fields.PromoPlatformCode != WindowsPromoPlatform || fields.Nonce != WindowsFixedNonce {
		t.Fatalf("unexpected Windows profile constants: %#v", fields)
	}
	wire, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte(`"openId":null`), []byte(`"userId":null`), []byte(`"packageName":"speedin"`)} {
		if !bytes.Contains(wire, expected) {
			t.Fatalf("missing Windows wire field %q in %s", expected, wire)
		}
	}
	for _, iosOnly := range [][]byte{[]byte(`"nickname"`), []byte(`"manufacture"`), []byte(`"virtualMachine"`), []byte(`"withSimCard"`), []byte(`"extra"`)} {
		if bytes.Contains(wire, iosOnly) {
			t.Fatalf("iOS-only field %q present in Windows request %s", iosOnly, wire)
		}
	}
}

func TestWindowsDefinition(t *testing.T) {
	t.Parallel()
	var definition Definition = Windows{}
	if definition.ID() != WindowsID || definition.UserAgent() != WindowsUserAgent || definition.RequiresPostLoginRefresh() {
		t.Fatalf("Windows definition = %#v", definition)
	}
	if eligible, err := definition.ValidateLine("WIFIIN", WindowsTunnelPassword); err != nil || !eligible {
		t.Fatalf("Windows WIFIIN eligibility = %t, %v", eligible, err)
	}
	if eligible, err := definition.ValidateLine("WS", ""); err != nil || eligible {
		t.Fatalf("Windows WS eligibility = %t, %v", eligible, err)
	}
}
