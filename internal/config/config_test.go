package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfig = `
management:
  listen: 127.0.0.1:10809
  sessionTTL: 30m
proxy:
  listen: 127.0.0.1:10808
  dialTimeout: 10s
  handshakeTimeout: 15s
provider:
  requestTimeout: 15s
  refreshInterval: 23h
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func replaceConfigLine(t *testing.T, body, old, replacement string) string {
	t.Helper()
	if !strings.Contains(body, old) {
		t.Fatalf("configuration line %q not found", old)
	}
	return strings.Replace(body, old, replacement, 1)
}

func configWithListener(t *testing.T, section, address string) string {
	t.Helper()
	old := "  listen: 127.0.0.1:10809\n"
	if section == "proxy" {
		old = "  listen: 127.0.0.1:10808\n"
	}
	return replaceConfigLine(t, validConfig, old, "  listen: \""+address+"\"\n")
}

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Management.Listen != "127.0.0.1:10809" ||
		cfg.Proxy.Listen != "127.0.0.1:10808" ||
		cfg.Management.SessionTTL.Value() != 30*time.Minute ||
		cfg.Proxy.DialTimeout.Value() != 10*time.Second ||
		cfg.Proxy.HandshakeTimeout.Value() != 15*time.Second ||
		cfg.Provider.RequestTimeout.Value() != 15*time.Second ||
		cfg.Provider.RefreshInterval.Value() != 23*time.Hour {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, "{}\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Management.Listen != "127.0.0.1:10809" || cfg.Proxy.Listen != "127.0.0.1:10808" {
		t.Fatalf("unexpected default listeners: %#v", cfg)
	}
	if cfg.Management.SessionTTL.Value() != 30*time.Minute ||
		cfg.Proxy.DialTimeout.Value() != 10*time.Second ||
		cfg.Proxy.HandshakeTimeout.Value() != 15*time.Second ||
		cfg.Provider.RequestTimeout.Value() != 15*time.Second ||
		cfg.Provider.RefreshInterval.Value() != 23*time.Hour {
		t.Fatalf("unexpected default durations: %#v", cfg)
	}
}

func TestLoadDerivesPublicAddresses(t *testing.T) {
	tests := []struct {
		name           string
		management     string
		proxy          string
		wantManagement string
		wantProxy      string
	}{
		{
			name:           "preserves canonical loopback listeners",
			management:     "127.0.0.2:18090",
			proxy:          "[::1]:18091",
			wantManagement: "127.0.0.2:18090",
			wantProxy:      "[::1]:18091",
		},
		{
			name:           "derives loopback addresses from wildcard ports",
			management:     "0.0.0.0:18090",
			proxy:          "[::]:18091",
			wantManagement: "127.0.0.1:18090",
			wantProxy:      "127.0.0.1:18091",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := configWithListener(t, "management", test.management)
			body = replaceConfigLine(t, body, "  listen: 127.0.0.1:10808\n", "  listen: \""+test.proxy+"\"\n")
			cfg, err := Load(writeConfig(t, body))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.ManagementAddress(); got != test.wantManagement {
				t.Fatalf("ManagementAddress() = %q, want %q", got, test.wantManagement)
			}
			if got := cfg.ProxyAddress(); got != test.wantProxy {
				t.Fatalf("ProxyAddress() = %q, want %q", got, test.wantProxy)
			}
		})
	}
}

func TestLoadRejectsLegacySchema(t *testing.T) {
	tests := []struct {
		name   string
		legacy string
	}{
		{name: "http.listen", legacy: "http:\n  listen: 127.0.0.1:10809\n"},
		{name: "http.advertise", legacy: "http:\n  advertise: 127.0.0.1:10809\n"},
		{name: "http.allowedHosts", legacy: "http:\n  allowedHosts: [127.0.0.1:10809]\n"},
		{name: "http.allowedOrigins", legacy: "http:\n  allowedOrigins: [http://127.0.0.1:10809]\n"},
		{name: "socks.listen", legacy: "socks:\n  listen: 127.0.0.1:10808\n"},
		{name: "socks.advertise", legacy: "socks:\n  advertise: 127.0.0.1:10808\n"},
		{name: "control.requestTimeout", legacy: "control:\n  requestTimeout: 15s\n"},
		{name: "control.refreshInterval", legacy: "control:\n  refreshInterval: 23h\n"},
		{name: "dataPlane.dialTimeout", legacy: "dataPlane:\n  dialTimeout: 10s\n"},
		{name: "dataPlane.handshakeTimeout", legacy: "dataPlane:\n  handshakeTimeout: 15s\n"},
		{name: "dataPlane.udpMode", legacy: "dataPlane:\n  udpMode: disabled_unverified\n"},
		{name: "security.sessionTTL", legacy: "security:\n  sessionTTL: 30m\n"},
		{name: "deployment.requireContainer", legacy: "deployment:\n  requireContainer: true\n"},
		{name: "deployment.networkMode", legacy: "deployment:\n  networkMode: bridge_loopback_publish\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, validConfig+test.legacy)); err == nil {
				t.Fatalf("Load accepted legacy field %s", test.name)
			}
		})
	}
}

func TestLoadRejectsRemovedAndUnknownFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "management advertise", body: strings.Replace(validConfig, "management:\n", "management:\n  advertise: 127.0.0.1:10809\n", 1)},
		{name: "management allowed hosts", body: strings.Replace(validConfig, "management:\n", "management:\n  allowedHosts: [127.0.0.1:10809]\n", 1)},
		{name: "management allowed origins", body: strings.Replace(validConfig, "management:\n", "management:\n  allowedOrigins: [http://127.0.0.1:10809]\n", 1)},
		{name: "proxy advertise", body: strings.Replace(validConfig, "proxy:\n", "proxy:\n  advertise: 127.0.0.1:10808\n", 1)},
		{name: "proxy udp mode", body: strings.Replace(validConfig, "proxy:\n", "proxy:\n  udpMode: disabled_unverified\n", 1)},
		{name: "unknown top level", body: validConfig + "unexpected: true\n"},
		{name: "unknown nested", body: strings.Replace(validConfig, "provider:\n", "provider:\n  unexpected: true\n", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, test.body)); err == nil {
				t.Fatal("Load accepted unknown field")
			}
		})
	}
}

func TestLoadValidatesListenerBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "IPv4 loopback minimum port", address: "127.0.0.1:1"},
		{name: "IPv4 loopback maximum port", address: "127.0.0.1:65535"},
		{name: "IPv6 loopback minimum port", address: "[::1]:1"},
		{name: "IPv6 loopback maximum port", address: "[::1]:65535"},
		{name: "IPv4 wildcard", address: "0.0.0.0:18090"},
		{name: "IPv6 wildcard", address: "[::]:18090"},
		{name: "zero port", address: "127.0.0.1:0", wantErr: true},
		{name: "negative port", address: "127.0.0.1:-1", wantErr: true},
		{name: "nonnumeric port", address: "127.0.0.1:http", wantErr: true},
		{name: "out of range port", address: "127.0.0.1:65536", wantErr: true},
		{name: "leading zero port", address: "127.0.0.1:010809", wantErr: true},
		{name: "unbracketed IPv6", address: "::1:10809", wantErr: true},
		{name: "expanded IPv6", address: "[0:0:0:0:0:0:0:1]:10809", wantErr: true},
		{name: "DNS host", address: "localhost:10809", wantErr: true},
		{name: "nonloopback host", address: "192.0.2.1:10809", wantErr: true},
	}
	for _, section := range []string{"management", "proxy"} {
		for _, test := range tests {
			t.Run(section+"/"+test.name, func(t *testing.T) {
				_, err := Load(writeConfig(t, configWithListener(t, section, test.address)))
				if test.wantErr {
					if err == nil || !strings.Contains(err.Error(), section+".listen") {
						t.Fatalf("Load error = %v, want %s.listen validation error", err, section)
					}
					return
				}
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
			})
		}
	}
}

func TestLoadRejectsSharedListenerPort(t *testing.T) {
	body := replaceConfigLine(t, validConfig, "  listen: 127.0.0.1:10809\n", "  listen: 127.0.0.2:10808\n")
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "management.listen and proxy.listen") {
		t.Fatalf("Load error = %v, want distinct-port error", err)
	}
}

func TestLoadValidatesDurationBounds(t *testing.T) {
	fields := []struct {
		name       string
		line       string
		prefix     string
		path       string
		minimum    string
		maximum    string
		belowRange string
		aboveRange string
	}{
		{name: "management session TTL", line: "  sessionTTL: 30m\n", prefix: "  sessionTTL: ", path: "management.sessionTTL", minimum: "1m", maximum: "24h", belowRange: "59s", aboveRange: "24h1s"},
		{name: "proxy dial timeout", line: "  dialTimeout: 10s\n", prefix: "  dialTimeout: ", path: "proxy.dialTimeout", minimum: "1s", maximum: "10s", belowRange: "999ms", aboveRange: "11s"},
		{name: "proxy handshake timeout", line: "  handshakeTimeout: 15s\n", prefix: "  handshakeTimeout: ", path: "proxy.handshakeTimeout", minimum: "1s", maximum: "1m", belowRange: "999ms", aboveRange: "1m1s"},
		{name: "provider request timeout", line: "  requestTimeout: 15s\n", prefix: "  requestTimeout: ", path: "provider.requestTimeout", minimum: "1s", maximum: "15s", belowRange: "999ms", aboveRange: "16s"},
		{name: "provider refresh interval", line: "  refreshInterval: 23h\n", prefix: "  refreshInterval: ", path: "provider.refreshInterval", minimum: "15m", maximum: "24h", belowRange: "14m59s", aboveRange: "24h1s"},
	}
	for _, field := range fields {
		for _, test := range []struct {
			name    string
			value   string
			wantErr bool
		}{
			{name: "minimum", value: field.minimum},
			{name: "maximum", value: field.maximum},
			{name: "below minimum", value: field.belowRange, wantErr: true},
			{name: "above maximum", value: field.aboveRange, wantErr: true},
		} {
			t.Run(field.name+"/"+test.name, func(t *testing.T) {
				body := replaceConfigLine(t, validConfig, field.line, field.prefix+test.value+"\n")
				_, err := Load(writeConfig(t, body))
				if test.wantErr {
					if err == nil || !strings.Contains(err.Error(), field.path) {
						t.Fatalf("Load error = %v, want %s range error", err, field.path)
					}
					return
				}
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
			})
		}
	}
}

func TestLoadRejectsNonPositiveDurations(t *testing.T) {
	fields := []struct {
		name   string
		line   string
		prefix string
	}{
		{name: "management session TTL", line: "  sessionTTL: 30m\n", prefix: "  sessionTTL: "},
		{name: "proxy dial timeout", line: "  dialTimeout: 10s\n", prefix: "  dialTimeout: "},
		{name: "proxy handshake timeout", line: "  handshakeTimeout: 15s\n", prefix: "  handshakeTimeout: "},
		{name: "provider request timeout", line: "  requestTimeout: 15s\n", prefix: "  requestTimeout: "},
		{name: "provider refresh interval", line: "  refreshInterval: 23h\n", prefix: "  refreshInterval: "},
	}
	for _, field := range fields {
		for _, value := range []string{"0s", "-1s"} {
			t.Run(field.name+"/"+value, func(t *testing.T) {
				body := replaceConfigLine(t, validConfig, field.line, field.prefix+value+"\n")
				if _, err := Load(writeConfig(t, body)); err == nil {
					t.Fatal("Load succeeded, want rejection")
				}
			})
		}
	}
}

func TestLoadRejectsMultipleDocumentsAndOversize(t *testing.T) {
	if _, err := Load(writeConfig(t, validConfig+"---\n{}\n")); err == nil {
		t.Fatal("expected multiple-document rejection")
	}
	if _, err := Load(writeConfig(t, validConfig+"#"+strings.Repeat("x", maxConfigBytes))); err == nil {
		t.Fatal("expected oversized configuration rejection")
	}
}
