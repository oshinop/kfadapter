// Package config loads and validates the adapter container configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/kfadapter/kfadapter/internal/endpoint"
	"gopkg.in/yaml.v3"
)

const (
	maxConfigBytes            = 64 << 10
	minProviderRequestTimeout = time.Second
	maxProviderRequestTimeout = 15 * time.Second
	minRefreshInterval        = 15 * time.Minute
	maxRefreshInterval        = 24 * time.Hour
	minProxyTimeout           = time.Second
	maxDialTimeout            = 10 * time.Second
	maxHandshakeTimeout       = time.Minute
	minSessionTTL             = time.Minute
	maxSessionTTL             = 24 * time.Hour
)

// Duration is a YAML duration such as "15s" or "2h".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("duration must be a string")
	}
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	if value <= 0 {
		return errors.New("duration must be positive")
	}
	*d = Duration(value)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.Value().String(), nil }

func (d Duration) Value() time.Duration { return time.Duration(d) }

// Port is a canonical decimal TCP port.
type Port uint16

func (p *Port) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" || !isCanonicalPort(node.Value) {
		return errors.New("port must be a decimal integer between 1 and 65535")
	}
	value, _ := strconv.ParseUint(node.Value, 10, 16)
	*p = Port(value)
	return nil
}

func (p Port) String() string { return strconv.FormatUint(uint64(p), 10) }

type Management struct {
	Port       Port     `yaml:"port"`
	SessionTTL Duration `yaml:"sessionTTL"`
}

type Proxy struct {
	Port             Port     `yaml:"port"`
	DialTimeout      Duration `yaml:"dialTimeout"`
	HandshakeTimeout Duration `yaml:"handshakeTimeout"`
}

type Provider struct {
	RequestTimeout  Duration `yaml:"requestTimeout"`
	RefreshInterval Duration `yaml:"refreshInterval"`
}

type Config struct {
	ListenAddr string     `yaml:"listenAddr"`
	Hostname   string     `yaml:"hostname,omitempty"`
	Management Management `yaml:"management"`
	Proxy      Proxy      `yaml:"proxy"`
	Provider   Provider   `yaml:"provider"`
}

func Load(path string) (Config, error) {
	file, err := openOrCreate(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(io.LimitReader(file, maxConfigBytes+1))
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("configuration contains multiple YAML documents")
		}
		return Config{}, fmt.Errorf("decode trailing configuration: %w", err)
	}
	if info, err := file.Stat(); err != nil {
		return Config{}, fmt.Errorf("stat configuration: %w", err)
	} else if info.Size() > maxConfigBytes {
		return Config{}, fmt.Errorf("configuration exceeds %d bytes", maxConfigBytes)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Default() Config {
	return Config{
		ListenAddr: "127.0.0.1",
		Management: Management{
			Port: 10809, SessionTTL: Duration(30 * time.Minute),
		},
		Proxy: Proxy{
			Port: 10808, DialTimeout: Duration(10 * time.Second), HandshakeTimeout: Duration(15 * time.Second),
		},
		Provider: Provider{
			RequestTimeout: Duration(15 * time.Second), RefreshInterval: Duration(2 * time.Hour),
		},
	}
}

func (c Config) ManagementAddress() string {
	return net.JoinHostPort(c.ListenAddr, c.Management.Port.String())
}

func (c Config) ProxyAddress() string { return net.JoinHostPort(c.ListenAddr, c.Proxy.Port.String()) }

func (c *Config) applyDefaults() {
	defaults := Default()
	if c.ListenAddr == "" {
		c.ListenAddr = defaults.ListenAddr
	}
	if c.Management.Port == 0 {
		c.Management.Port = defaults.Management.Port
	}
	if c.Management.SessionTTL == 0 {
		c.Management.SessionTTL = defaults.Management.SessionTTL
	}
	if c.Proxy.Port == 0 {
		c.Proxy.Port = defaults.Proxy.Port
	}
	if c.Proxy.DialTimeout == 0 {
		c.Proxy.DialTimeout = defaults.Proxy.DialTimeout
	}
	if c.Proxy.HandshakeTimeout == 0 {
		c.Proxy.HandshakeTimeout = defaults.Proxy.HandshakeTimeout
	}
	if c.Provider.RequestTimeout == 0 {
		c.Provider.RequestTimeout = defaults.Provider.RequestTimeout
	}
	if c.Provider.RefreshInterval == 0 {
		c.Provider.RefreshInterval = defaults.Provider.RefreshInterval
	}
}

func (c Config) Validate() error {
	if err := validateListen("listenAddr", c.ListenAddr); err != nil {
		return err
	}
	if err := validateHostname("hostname", c.Hostname); err != nil {
		return err
	}
	if c.Management.Port == c.Proxy.Port {
		return errors.New("management.port and proxy.port must be different")
	}
	if err := validateDurationRange("management.sessionTTL", c.Management.SessionTTL.Value(), minSessionTTL, maxSessionTTL); err != nil {
		return err
	}
	if err := validateDurationRange("proxy.dialTimeout", c.Proxy.DialTimeout.Value(), minProxyTimeout, maxDialTimeout); err != nil {
		return err
	}
	if err := validateDurationRange("proxy.handshakeTimeout", c.Proxy.HandshakeTimeout.Value(), minProxyTimeout, maxHandshakeTimeout); err != nil {
		return err
	}
	if err := validateDurationRange("provider.requestTimeout", c.Provider.RequestTimeout.Value(), minProviderRequestTimeout, maxProviderRequestTimeout); err != nil {
		return err
	}
	if err := validateDurationRange("provider.refreshInterval", c.Provider.RefreshInterval.Value(), minRefreshInterval, maxRefreshInterval); err != nil {
		return err
	}
	return nil
}

func openOrCreate(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return file, err
	}
	if err := writeDefault(path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.Open(path)
		}
		return nil, fmt.Errorf("create default configuration: %w", err)
	}
	return os.Open(path)
}

func writeDefault(path string) error {
	contents, err := yaml.Marshal(Default())
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

func validateListen(name, address string) error {
	addr, err := netip.ParseAddr(address)
	if err != nil || addr.String() != address {
		return fmt.Errorf("%s must be a canonical numeric IP address", name)
	}
	return nil
}

func validateHostname(name, hostname string) error {
	if hostname == "" {
		return nil
	}
	if err := endpoint.ValidateHostname(hostname); err != nil {
		return fmt.Errorf("%s %w", name, err)
	}
	return nil
}

func isCanonicalPort(port string) bool {
	if len(port) == 0 || (len(port) > 1 && port[0] == '0') {
		return false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	return err == nil && parsedPort > 0
}

func validateDurationRange(name string, value, minimum, maximum time.Duration) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return nil
}
