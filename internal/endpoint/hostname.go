// Package endpoint validates hostnames shared by configuration and advertised endpoints.
package endpoint

import (
	"errors"
	"net/netip"
	"strings"
)

var errInvalidHostname = errors.New("must be a bare DNS hostname")

// ValidateHostname accepts an ASCII DNS hostname without a scheme, port, or trailing dot.
func ValidateHostname(hostname string) error {
	if hostname == "" || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return errInvalidHostname
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errInvalidHostname
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return errInvalidHostname
			}
		}
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return errInvalidHostname
	}
	return nil
}
