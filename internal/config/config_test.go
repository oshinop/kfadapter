package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfig = `
listenAddr: 127.0.0.1
hostname: adapter.example.com
management:
  port: 10809
  sessionTTL: 30m
proxy:
  port: 10808
  dialTimeout: 10s
  handshakeTimeout: 15s
provider:
  requestTimeout: 15s
  refreshInterval: 2h
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
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

func configWithListenAddr(t *testing.T, listenAddr string) string {
	t.Helper()
	return replaceConfigLine(t, validConfig, "listenAddr: 127.0.0.1\n", "listenAddr: \""+listenAddr+"\"\n")
}

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1" || cfg.Hostname != "adapter.example.com" ||
		cfg.Management.Port != 10809 || cfg.Proxy.Port != 10808 ||
		cfg.ManagementAddress() != "127.0.0.1:10809" || cfg.ProxyAddress() != "127.0.0.1:10808" ||
		cfg.Management.SessionTTL.Value() != 30*time.Minute || cfg.Proxy.DialTimeout.Value() != 10*time.Second ||
		cfg.Proxy.HandshakeTimeout.Value() != 15*time.Second || cfg.Provider.RequestTimeout.Value() != 15*time.Second ||
		cfg.Provider.RefreshInterval.Value() != 2*time.Hour {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadAppliesLoopbackDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, "{}\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg != Default() {
		t.Fatalf("defaults = %#v, want %#v", cfg, Default())
	}
	if cfg.ListenAddr != "127.0.0.1" || cfg.Management.Port != 10809 || cfg.Proxy.Port != 10808 {
		t.Fatalf("unexpected default listeners: %#v", cfg)
	}
}

func TestLoadCreatesDefaultConfigWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load missing config: %v", err)
	}
	if cfg != Default() {
		t.Fatalf("created config = %#v, want %#v", cfg, Default())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("created config mode = %s", info.Mode())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "hostname:") {
		t.Fatalf("empty optional hostname was written: %s", contents)
	}
}

func TestLoadAcceptsAnyCanonicalNumericListener(t *testing.T) {
	for _, listenAddr := range []string{"127.0.0.2", "0.0.0.0", "192.0.2.1", "::1", "::", "2001:db8::1"} {
		t.Run(listenAddr, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, configWithListenAddr(t, listenAddr)))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.ListenAddr != listenAddr {
				t.Fatalf("listenAddr = %q, want %q", cfg.ListenAddr, listenAddr)
			}
		})
	}
}

func TestLoadRejectsInvalidListeners(t *testing.T) {
	for _, listenAddr := range []string{"localhost", "127.0.0.1:10809", "0:0:0:0:0:0:0:1", " 127.0.0.1"} {
		t.Run(listenAddr, func(t *testing.T) {
			_, err := Load(writeConfig(t, configWithListenAddr(t, listenAddr)))
			if err == nil || !strings.Contains(err.Error(), "listenAddr") {
				t.Fatalf("Load error = %v, want listenAddr validation error", err)
			}
		})
	}
}

func TestLoadValidatesOptionalHostname(t *testing.T) {
	for _, hostname := range []string{"localhost", "kfadapter", "adapter.example.com", "KF-Adapter.Example"} {
		t.Run("valid/"+hostname, func(t *testing.T) {
			body := replaceConfigLine(t, validConfig, "hostname: adapter.example.com\n", "hostname: "+hostname+"\n")
			if _, err := Load(writeConfig(t, body)); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
	for _, hostname := range []string{"adapter.example.com:10809", "http://adapter.example.com", "adapter.example.com.", "bad_name", "127.0.0.1", "-bad.example", "bad-.example"} {
		t.Run("invalid/"+hostname, func(t *testing.T) {
			body := replaceConfigLine(t, validConfig, "hostname: adapter.example.com\n", "hostname: \""+hostname+"\"\n")
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), "hostname") {
				t.Fatalf("Load error = %v, want hostname validation error", err)
			}
		})
	}
}

func TestLoadValidatesPorts(t *testing.T) {
	for _, port := range []string{"1", "65535"} {
		t.Run("valid/"+port, func(t *testing.T) {
			body := replaceConfigLine(t, validConfig, "  port: 10809\n", "  port: "+port+"\n")
			if _, err := Load(writeConfig(t, body)); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
	for _, port := range []string{"0", "-1", "010809", "65536", "\"10809\""} {
		t.Run("invalid/"+port, func(t *testing.T) {
			body := replaceConfigLine(t, validConfig, "  port: 10809\n", "  port: "+port+"\n")
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatal("Load accepted invalid port")
			}
		})
	}
}

func TestLoadRejectsIdenticalPorts(t *testing.T) {
	body := replaceConfigLine(t, validConfig, "  port: 10809\n", "  port: 10808\n")
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("identical ports error = %v", err)
	}
}

func TestLoadRejectsRemovedAndUnknownFields(t *testing.T) {
	for name, body := range map[string]string{
		"removed top listen":  strings.Replace(validConfig, "listenAddr: 127.0.0.1\n", "listen: 127.0.0.1\n", 1),
		"management listen":   strings.Replace(validConfig, "management:\n", "management:\n  listen: 127.0.0.1:10809\n", 1),
		"management hostname": strings.Replace(validConfig, "management:\n", "management:\n  hostname: adapter.example.com\n", 1),
		"proxy listen":        strings.Replace(validConfig, "proxy:\n", "proxy:\n  listen: 127.0.0.1:10808\n", 1),
		"top port":            strings.Replace(validConfig, "listenAddr: 127.0.0.1\n", "listenAddr: 127.0.0.1\nport: 10809\n", 1),
		"unknown nested":      strings.Replace(validConfig, "provider:\n", "provider:\n  unexpected: true\n", 1),
		"unknown top":         validConfig + "unexpected: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatal("Load accepted unknown field")
			}
		})
	}
}

func TestLoadValidatesDurationBounds(t *testing.T) {
	fields := []struct {
		line, path, minimum, maximum string
	}{
		{"  sessionTTL: 30m\n", "management.sessionTTL", "59s", "24h1s"},
		{"  dialTimeout: 10s\n", "proxy.dialTimeout", "999ms", "11s"},
		{"  handshakeTimeout: 15s\n", "proxy.handshakeTimeout", "999ms", "1m1s"},
		{"  requestTimeout: 15s\n", "provider.requestTimeout", "999ms", "16s"},
		{"  refreshInterval: 2h\n", "provider.refreshInterval", "14m59s", "24h1s"},
	}
	for _, field := range fields {
		for _, value := range []string{field.minimum, field.maximum, "0s", "-1s"} {
			t.Run(field.path+"/"+value, func(t *testing.T) {
				body := replaceConfigLine(t, validConfig, field.line, strings.Split(field.line, ":")[0]+": "+value+"\n")
				_, err := Load(writeConfig(t, body))
				if err == nil {
					t.Fatalf("Load accepted %s", value)
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
