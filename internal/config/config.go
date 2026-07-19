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

// Duration is a YAML duration such as "15s" or "23h".
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

func (d Duration) Value() time.Duration { return time.Duration(d) }

type Management struct {
	Listen     string   `yaml:"listen"`
	SessionTTL Duration `yaml:"sessionTTL"`
}

type Proxy struct {
	Listen           string   `yaml:"listen"`
	DialTimeout      Duration `yaml:"dialTimeout"`
	HandshakeTimeout Duration `yaml:"handshakeTimeout"`
}

type Provider struct {
	RequestTimeout  Duration `yaml:"requestTimeout"`
	RefreshInterval Duration `yaml:"refreshInterval"`
}

type Config struct {
	Management Management `yaml:"management"`
	Proxy      Proxy      `yaml:"proxy"`
	Provider   Provider   `yaml:"provider"`
}

func (c Config) ManagementAddress() string {
	return loopbackAddress(c.Management.Listen)
}

func (c Config) ProxyAddress() string {
	return loopbackAddress(c.Proxy.Listen)
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
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

func (c *Config) applyDefaults() {
	if c.Management.Listen == "" {
		c.Management.Listen = "127.0.0.1:10809"
	}
	if c.Management.SessionTTL == 0 {
		c.Management.SessionTTL = Duration(30 * time.Minute)
	}
	if c.Proxy.Listen == "" {
		c.Proxy.Listen = "127.0.0.1:10808"
	}
	if c.Proxy.DialTimeout == 0 {
		c.Proxy.DialTimeout = Duration(10 * time.Second)
	}
	if c.Proxy.HandshakeTimeout == 0 {
		c.Proxy.HandshakeTimeout = Duration(15 * time.Second)
	}
	if c.Provider.RequestTimeout == 0 {
		c.Provider.RequestTimeout = Duration(15 * time.Second)
	}
	if c.Provider.RefreshInterval == 0 {
		c.Provider.RefreshInterval = Duration(23 * time.Hour)
	}
}

func (c Config) Validate() error {
	if err := validateListener("management.listen", c.Management.Listen); err != nil {
		return err
	}
	if err := validateListener("proxy.listen", c.Proxy.Listen); err != nil {
		return err
	}
	if listenerPort(c.Management.Listen) == listenerPort(c.Proxy.Listen) {
		return errors.New("management.listen and proxy.listen must use different ports")
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

func loopbackAddress(listener string) string {
	host, port, err := net.SplitHostPort(listener)
	if err != nil {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.IsLoopback() && addr.String() == host {
		return listener
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func validateListener(name, address string) error {
	if validateCanonicalLoopbackHostPort(name, address) == nil || isCanonicalWildcardHostPort(address) {
		return nil
	}
	return fmt.Errorf("%s must use a canonical numeric loopback or wildcard host:port", name)
}

func listenerPort(address string) string {
	_, port, _ := net.SplitHostPort(address)
	return port
}

func isCanonicalWildcardHostPort(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !isCanonicalPort(port) {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsUnspecified() || addr.String() != host {
		return false
	}
	return net.JoinHostPort(addr.String(), port) == address
}

func validateCanonicalLoopbackHostPort(name, address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s must use a canonical literal loopback host:port", name)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() || addr.String() != host {
		return fmt.Errorf("%s must use a canonical literal loopback host:port", name)
	}
	if !isCanonicalPort(port) {
		return fmt.Errorf("%s must use a canonical literal loopback host:port", name)
	}
	if net.JoinHostPort(addr.String(), port) != address {
		return fmt.Errorf("%s must use a canonical literal loopback host:port", name)
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
