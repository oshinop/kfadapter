package control

import (
	"bytes"
	"testing"
)

func TestComputeVerifyGolden(t *testing.T) {
	t.Parallel()
	verify, err := ComputeVerify(DefaultSyntheticMAC, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	const golden = "MjNkYWFmYjAAANVjNDU2YjVmODRjYzFiOTI5NGY3M2E4Njk="
	if verify != golden {
		t.Fatalf("verify = %q, want %q", verify, golden)
	}
}

func TestBuildEmailLoginFieldsUsesOnlySyntheticIdentifiers(t *testing.T) {
	t.Parallel()
	fields, err := BuildEmailLoginFields(EmailLogin{
		Account: "person@example.test", Password: "not-persisted", InstallationID: "random-install-id",
	}, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if fields.LoginType != 4 || fields.MAC != DefaultSyntheticMAC || fields.IMEI != "" || fields.UserID != "" {
		t.Fatalf("unexpected email defaults: %#v", fields)
	}
	for _, identifier := range []string{fields.DeviceID, fields.UDID, fields.OpenUDID, fields.UUID, fields.IDFA} {
		if identifier != "random-install-id" {
			t.Fatalf("identifier mismatch: %q", identifier)
		}
	}
	if fields.Signature != fields.Certification || fields.Extra == nil || len(fields.Extra) != 0 {
		t.Fatalf("invalid observed constants")
	}
}

func TestSyntheticMACRequiresLowercaseUnseparatedHex(t *testing.T) {
	t.Parallel()
	if DefaultSyntheticMAC != "020000000000" || !validSyntheticMAC(DefaultSyntheticMAC) {
		t.Fatalf("default synthetic MAC = %q", DefaultSyntheticMAC)
	}
	for _, mac := range []string{"02:00:00:00:00:00", "02000000000A", "02000000000g", "02000000000"} {
		if validSyntheticMAC(mac) {
			t.Fatalf("invalid MAC accepted: %q", mac)
		}
		if _, err := ComputeVerify(mac, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0})); err != ErrInvalidVerifyInput {
			t.Fatalf("ComputeVerify(%q) error = %v", mac, err)
		}
		if _, err := BuildEmailLoginFields(EmailLogin{Account: "person@example.test", Password: "password", InstallationID: "id", MAC: mac}, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0})); err != ErrInvalidVerifyInput {
			t.Fatalf("BuildEmailLoginFields(%q) error = %v", mac, err)
		}
	}
}
