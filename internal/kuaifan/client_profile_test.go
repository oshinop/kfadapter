package kuaifan

import (
	"encoding/json"
	"testing"

	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"github.com/kfadapter/kfadapter/internal/state"
)

func TestWindowsLineValidationRetainsUnsupportedWSAsIneligible(t *testing.T) {
	t.Parallel()
	fields := windowsRawFields(t, map[string]any{
		"groups": []any{map[string]any{"id": "g", "name": "group"}},
		"lines": []any{
			map[string]any{"host": "wifiin.example", "port": 11000, "provider": "WIFIIN", "password": wireprofile.WindowsTunnelPassword, "groupId": "g"},
			map[string]any{"host": "ws.example", "port": 12000, "provider": "WS", "groupId": "g"},
		},
	})
	lines, err := validateLinesForProfile(fields, "zh-CN", windowsClientProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines.Lines) != 2 || !lines.Lines[0].Eligible || lines.Lines[1].Eligible {
		t.Fatalf("Windows line eligibility = %#v", lines.Lines)
	}
}

func TestConstructorsKeepProfileBoundary(t *testing.T) {
	t.Parallel()
	ios, err := NewIOSClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	windows, err := NewWindowsClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if ios.Profile() != state.ClientProfileIOS || windows.Profile() != state.ClientProfileWindows {
		t.Fatalf("profiles = %q / %q", ios.Profile(), windows.Profile())
	}
}

func windowsRawFields(t *testing.T, values map[string]any) map[string]json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}
