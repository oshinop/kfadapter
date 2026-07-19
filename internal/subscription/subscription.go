// Package subscription renders and serves local SOCKS5 subscriptions.
package subscription

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kfadapter/kfadapter/internal/endpoint"
)

const (
	// MaxRenderedBytes bounds one subscription response body.
	MaxRenderedBytes = 10 << 20
)

var (
	ErrNoEligibleLinks         = errors.New("subscription has no eligible links")
	ErrRenderedTooLarge        = errors.New("subscription exceeds response size limit")
	ErrSubscriptionUnavailable = errors.New("subscription is not activated")
	ErrInvalidAddress          = errors.New("subscription SOCKS address must contain a canonical numeric IP address and port")
)

// Link is the non-secret presentation data required to render one local SOCKS URI.
// Selector and Password are derived local credentials, never provider credentials.
type Link struct {
	Selector string
	Password string
	Name     string
	Group    string
	Eligible bool
}

// Metadata is safe for the ordinary authenticated browser API. It intentionally
// contains neither the stable URL token nor derived SOCKS credentials.
type Metadata struct {
	Active                bool      `json:"active"`
	Generation            uint64    `json:"generation"`
	NodeCount             int       `json:"nodeCount"`
	LastFetchedAt         time.Time `json:"lastFetchedAt,omitempty"`
	LastFetchedGeneration uint64    `json:"lastFetchedGeneration,omitempty"`
	ReloadRecommended     bool      `json:"reloadRecommended"`
}

// Render emits padded Base64 of deterministic newline-delimited SOCKS5 links.
func Render(links []Link, socksAddress string) (string, int, error) {
	host, port, err := parseAddress(socksAddress)
	if err != nil {
		return "", 0, err
	}
	eligible := make([]Link, 0, len(links))
	for _, link := range links {
		if !link.Eligible {
			continue
		}
		if link.Selector == "" || link.Password == "" || strings.IndexByte(link.Selector, 0) >= 0 || strings.IndexByte(link.Password, 0) >= 0 {
			return "", 0, errors.New("invalid local SOCKS credential")
		}
		eligible = append(eligible, link)
	}
	if len(eligible) == 0 {
		return "", 0, ErrNoEligibleLinks
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Group != eligible[j].Group {
			return eligible[i].Group < eligible[j].Group
		}
		if eligible[i].Name != eligible[j].Name {
			return eligible[i].Name < eligible[j].Name
		}
		return eligible[i].Selector < eligible[j].Selector
	})
	var text strings.Builder
	for _, link := range eligible {
		u := &url.URL{
			Scheme: "socks5", User: url.UserPassword(link.Selector, link.Password),
			Host: net.JoinHostPort(host, port), Fragment: link.Name,
		}
		text.WriteString(u.String())
		text.WriteByte('\n')
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(text.String()))
	if len(encoded) > MaxRenderedBytes {
		return "", 0, ErrRenderedTooLarge
	}
	return encoded, len(eligible), nil
}

func parseAddress(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", ErrInvalidAddress
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 || strconv.FormatUint(portNumber, 10) != port {
		return "", "", ErrInvalidAddress
	}
	ip, err := netip.ParseAddr(host)
	if err == nil && ip.Zone() == "" && ip.String() == host {
		return ip.String(), port, nil
	}
	if endpoint.ValidateHostname(host) != nil {
		return "", "", ErrInvalidAddress
	}
	return host, port, nil
}

func validateAddress(address string) error {
	_, _, err := parseAddress(address)
	return err
}

func subscriptionURL(baseURL, binding string) string {
	return strings.TrimRight(baseURL, "/") + "/sub/" + binding
}

func writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
}
