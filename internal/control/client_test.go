package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func encryptedHTTPResponse(t *testing.T, value any) *http.Response {
	t.Helper()
	encoded, err := EncodeRequest(value)
	if err != nil {
		t.Fatalf("encode fake response: %v", err)
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(encoded)),
		Body:          io.NopCloser(bytes.NewReader(encoded)),
		Header:        make(http.Header),
	}
}

func TestClientUsesHTTPSAllowlistHeadersAndDistinctTokens(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]map[string]any)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json; UTF-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := request.Header.Get("User-Agent"); got != controlUA {
			t.Errorf("User-Agent = %q", got)
		}
		encoded, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := DecodeResponse(encoded, &fields); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		mu.Lock()
		requests[request.URL.Host+request.URL.Path] = fields
		mu.Unlock()
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": "", "fields": map[string]any{"domain": map[string]any{"ws": "api.example"}}}), nil
		case "/v4/user/login.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 119, "msg": "", "fields": map[string]any{"token": "login-token", "userId": 7}}), nil
		case "/v4/invpn/getAuthority.do":
			authKey, err := AuthorityCodec().EncodeJSON(map[string]any{
				"userId": "7", "partnerKey": "p", "encryptKey": "tunnel-key", "encryptType": "AES-256-CFB", "partnerStatus": "ok", "orderId": "order-4",
			})
			if err != nil {
				t.Fatal(err)
			}
			return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": "", "fields": map[string]any{"authKey": string(authKey), "token": "provider-token"}}), nil
		case "/v4/invpn/getLines.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": "", "fields": map[string]any{
				"groups": []any{map[string]any{"id": "g1", "name": "Group One"}},
				"lines":  []any{map[string]any{"text": "Tokyo", "host": "node.example", "port": 11000, "provider": "WIFIIN", "groupId": "g1", "password": "must-not-be-used"}},
			}}), nil
		default:
			return nil, errors.New("unexpected route")
		}
	})
	fixedTime := time.Date(2026, 7, 15, 10, 11, 12, 123000000, time.UTC)
	client, err := NewClient(Config{
		httpClient:      &http.Client{Transport: transport},
		BootstrapBase:   "https://bootstrap.example",
		AllowedAPIHosts: []string{"bootstrap.example", "api.example"},
		Clock:           func() time.Time { return fixedTime },
		Location:        time.UTC,
		Random:          bytes.NewReader(bytes.Repeat([]byte{0}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Login(context.Background(), EmailLogin{Account: "alice@example.test", Password: "password", InstallationID: "install-id", OSVersion: "test-os"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	authority, err := client.FetchAuthority(context.Background(), session)
	if err != nil {
		t.Fatalf("FetchAuthority: %v", err)
	}
	lines, err := client.FetchLines(context.Background(), session)
	if err != nil {
		t.Fatalf("FetchLines: %v", err)
	}
	if authority.ProviderToken != "provider-token" || authority.ProviderExtension != "|provider-token|cc.fancast.major|order-4|7|MAC|1.0.46" {
		t.Fatalf("authority did not preserve provider token separately")
	}
	if len(lines.Lines) != 1 || lines.Lines[0].Host != "node.example" || lines.Lines[0].Port != 11000 {
		t.Fatalf("validated lines = %#v", lines)
	}

	mu.Lock()
	defer mu.Unlock()
	login := requests["api.example/v4/user/login.do"]
	if login["deviceId"] != "install-id" || login["udid"] != "install-id" || login["openUdid"] != "install-id" || login["uuid"] != "install-id" || login["idfa"] != "install-id" {
		t.Fatalf("installation identifier fields diverged: %#v", login)
	}
	if login["loginType"] != float64(4) || login["imei"] != "" || login["userId"] != "" || login["mac"] != DefaultSyntheticMAC {
		t.Fatalf("email schema is not privacy-safe: %#v", login)
	}
	for route, fields := range requests {
		if fields["lang"] != "zh-CN" || len(fields["nonce"].(string)) != 8 || fields["time"] != "20260715101112123" {
			t.Fatalf("common envelope on %s = %#v", route, fields)
		}
	}
	if authorityRequest := requests["api.example/v4/invpn/getAuthority.do"]; authorityRequest["token"] != "login-token" {
		t.Fatalf("authority token = %q, want login token", authorityRequest["token"])
	}
	if linesRequest := requests["api.example/v4/invpn/getLines.do"]; linesRequest["token"] != "login-token" {
		t.Fatalf("lines token = %q, want login token", linesRequest["token"])
	}
}

func TestClientRejectsInsecureOrUnapprovedAPIBase(t *testing.T) {
	t.Parallel()
	for _, base := range []string{"http://ws.kuaifan.co", "https://attacker.example", "https://ws.kuaifan.co/path", "https://ws.kuaifan.co?x=1"} {
		if _, err := NewClient(Config{BootstrapBase: base}); !errors.Is(err, ErrUnapprovedAPIBase) {
			t.Errorf("NewClient(%q) error = %v, want ErrUnapprovedAPIBase", base, err)
		}
	}
	client, err := NewClient(Config{BootstrapBase: "https://ws.kuaifan.co"})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("default client transport is not TLS-validating: %#v", client.httpClient.Transport)
	}
	if err := client.httpClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v", err)
	}
	if _, err := client.APIBase("http://ws.kuaifan.co"); !errors.Is(err, ErrUnapprovedAPIBase) {
		t.Fatalf("HTTP API base error = %v", err)
	}
	if _, err := NewClient(Config{BootstrapBase: "https://ws.kuaifan.co", httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}); !errors.Is(err, ErrInsecureTLS) {
		t.Fatalf("insecure TLS client error = %v", err)
	}
}

func TestHardenedHTTPClientBypassesEnvironmentProxies(t *testing.T) {
	var mu sync.Mutex
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		proxyHits++
		mu.Unlock()
		t.Error("environment proxy received a control request")
	}))
	defer proxy.Close()
	targetHits := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		targetHits++
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(key, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	client := hardenedHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil {
		t.Fatalf("hardened transport retained a proxy path: %#v", client.Transport)
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	transport.TLSClientConfig.RootCAs = roots
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("direct TLS request: %v", err)
	}
	response.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if targetHits != 1 || proxyHits != 0 {
		t.Fatalf("request routing: target=%d proxy=%d", targetHits, proxyHits)
	}
}

func TestAPIBaseRequiresCanonicalExplicitPort(t *testing.T) {
	client, err := NewClient(Config{BootstrapBase: "https://bootstrap.example", AllowedAPIHosts: []string{"bootstrap.example", "api.example"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://api.example:443", "https://api.example:8443"} {
		base, err := client.APIBase(raw)
		if err != nil || base.String() != raw {
			t.Fatalf("valid base %q = %v, %v", raw, base, err)
		}
	}
	invalid := []string{
		"https://api.example:0",
		"https://api.example:65536",
		"https://api.example:000443",
		"https://api.example:",
		"https://api.example:01",
		"https://api.example:abc",
		"https://unapproved.example:443",
	}
	for _, raw := range invalid {
		if _, err := client.APIBase(raw); !errors.Is(err, ErrUnapprovedAPIBase) {
			t.Errorf("invalid base %q error = %v", raw, err)
		}
	}
	for _, domain := range []string{"api.example:0", "api.example:65536", "api.example:000443", "api.example:", "api.example:01", "api.example:abc"} {
		t.Run(domain, func(t *testing.T) {
			fallback, err := NewClient(Config{
				BootstrapBase: "https://bootstrap.example", AllowedAPIHosts: []string{"bootstrap.example", "api.example"},
				httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return encryptedHTTPResponse(t, envelope(map[string]any{"domain": map[string]any{"ws": domain}})), nil
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := fallback.FetchClientConfig(context.Background())
			if err != nil || configuration.APIBase.String() != "https://bootstrap.example" {
				t.Fatalf("malformed replacement %q configuration = %#v, %v", domain, configuration, err)
			}
		})
	}
}

func TestExplicitAPIAllowlistDoesNotInjectDefaultHost(t *testing.T) {
	defaultHosts, err := normalizedAllowlist(nil)
	if err != nil || len(defaultHosts) != 1 {
		t.Fatalf("default allowlist = %#v, %v", defaultHosts, err)
	}
	if _, ok := defaultHosts["ws.kuaifan.co"]; !ok {
		t.Fatal("empty allowlist did not use documented default host")
	}
	customHosts, err := normalizedAllowlist([]string{"API.Example."})
	if err != nil || len(customHosts) != 1 {
		t.Fatalf("custom allowlist = %#v, %v", customHosts, err)
	}
	if _, ok := customHosts["api.example"]; !ok {
		t.Fatalf("case/trailing-dot normalization lost custom host: %#v", customHosts)
	}
	if _, ok := customHosts["ws.kuaifan.co"]; ok {
		t.Fatalf("custom allowlist unexpectedly contains default host: %#v", customHosts)
	}
	calls := 0
	if _, err := NewClient(Config{
		BootstrapBase: "https://ws.kuaifan.co", AllowedAPIHosts: []string{"api.example"},
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("must not request excluded bootstrap")
		})},
	}); !errors.Is(err, ErrUnapprovedAPIBase) || calls != 0 {
		t.Fatalf("excluded bootstrap error/calls = %v/%d", err, calls)
	}
	if _, err := NewClient(Config{BootstrapBase: "https://ws.kuaifan.co", AllowedAPIHosts: []string{"api.example", "ws.kuaifan.co"}}); err != nil {
		t.Fatalf("explicit default allowlist host rejected: %v", err)
	}
	client, err := NewClient(Config{BootstrapBase: "https://api.example", AllowedAPIHosts: []string{"API.EXAMPLE."}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.APIBase("https://api.example:000443"); !errors.Is(err, ErrUnapprovedAPIBase) {
		t.Fatalf("noncanonical API base port error = %v", err)
	}
}

func TestAuthorityRejectsInvalidProviderExtensionFields(t *testing.T) {
	base := mustBase(t, "https://api.example")
	session := LoginSession{UserID: 7, Token: "login", APIBase: base}
	for _, test := range []struct {
		name          string
		providerToken string
		orderID       string
	}{
		{name: "pipe token", providerToken: "provider|token", orderID: "order"},
		{name: "NUL token", providerToken: "provider\x00token", orderID: "order"},
		{name: "control token", providerToken: "provider\x1ftoken", orderID: "order"},
		{name: "DEL token", providerToken: "provider\x7ftoken", orderID: "order"},
		{name: "non-ASCII token", providerToken: "providér", orderID: "order"},
		{name: "pipe order", providerToken: "provider", orderID: "order|id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			authKey, err := AuthorityCodec().EncodeJSON(map[string]any{"userId": 7, "encryptKey": "tunnel", "encryptType": "aes-256-cfb", "orderId": test.orderID})
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewClient(Config{
				BootstrapBase: "https://api.example", AllowedAPIHosts: []string{"api.example"},
				httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": test.providerToken})), nil
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.FetchAuthority(context.Background(), session); !errors.Is(err, ErrSchema) {
				t.Fatalf("FetchAuthority error = %v, want ErrSchema", err)
			}
		})
	}
	providerExtension, err := buildProviderExtension("provider-live", "order-live", "7")
	if err != nil || providerExtension != "|provider-live|cc.fancast.major|order-live|7|MAC|1.0.46" {
		t.Fatalf("valid provider extension = %q, %v", providerExtension, err)
	}
}

func TestClientRejectsMalformedOversizedAuthorityAndLines(t *testing.T) {
	t.Parallel()
	base := "https://api.example"
	makeClient := func(responder func(*http.Request) *http.Response) *Client {
		client, err := NewClient(Config{httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return responder(request), nil
		})}, BootstrapBase: base, AllowedAPIHosts: []string{"api.example"}, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64))})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	session := LoginSession{UserID: 1, Token: "login", APIBase: mustBase(t, base)}
	malformed := makeClient(func(*http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(stringReader("plain-json")), Header: make(http.Header)}
	})
	if _, err := malformed.FetchAuthority(context.Background(), session); err == nil {
		t.Fatal("plaintext authority response was accepted")
	}
	oversized := makeClient(func(*http.Request) *http.Response {
		body := bytes.Repeat([]byte{'A'}, base64MaximumEncodedSize()+1)
		return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}
	})
	if _, err := oversized.FetchLines(context.Background(), session); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
	invalidLines := makeClient(func(*http.Request) *http.Response {
		return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": "", "fields": map[string]any{
			"groups": []any{map[string]any{"id": "g1"}},
			"lines":  []any{map[string]any{"host": "node.example", "port": 1, "provider": "WIFIIN", "groupId": "missing"}},
		}})
	})
	if _, err := invalidLines.FetchLines(context.Background(), session); !errors.Is(err, ErrInvalidLine) {
		t.Fatalf("invalid group reference error = %v", err)
	}
	wrongAuthority := makeClient(func(*http.Request) *http.Response {
		authKey, err := AuthorityCodec().EncodeJSON(map[string]any{
			"userId": "other-user", "encryptKey": "key", "encryptType": "aes-256-cfb", "orderId": "order",
		})
		if err != nil {
			t.Fatal(err)
		}
		return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": "", "fields": map[string]any{"authKey": string(authKey), "token": "provider"}})
	})
	if _, err := wrongAuthority.FetchAuthority(context.Background(), session); !errors.Is(err, ErrSchema) {
		t.Fatalf("mismatched authority user error = %v", err)
	}
}

func TestResponseMessageIsOptionalButBounded(t *testing.T) {
	accepted := []map[string]any{
		{"status": 1, "msg": nil, "fields": map[string]any{}},
		{"status": 1, "fields": map[string]any{}},
	}
	for index, payload := range accepted {
		client, err := NewClient(Config{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return encryptedHTTPResponse(t, payload), nil
		})}, BootstrapBase: "https://api.example", AllowedAPIHosts: []string{"api.example"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.FetchClientConfig(context.Background()); err != nil {
			t.Fatalf("optional message fixture %d rejected: %v", index, err)
		}
	}
	for _, payload := range []map[string]any{
		{"status": 1, "msg": strings.Repeat("m", maxControlFieldBytes+1), "fields": map[string]any{}},
		{"status": 1, "msg": map[string]any{"not": "a string"}, "fields": map[string]any{}},
	} {
		client, err := NewClient(Config{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return encryptedHTTPResponse(t, payload), nil
		})}, BootstrapBase: "https://api.example", AllowedAPIHosts: []string{"api.example"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.FetchClientConfig(context.Background()); err == nil {
			t.Fatal("invalid response message was accepted")
		}
	}
}

func TestNullResponseFieldsReachEndpointStatusHandling(t *testing.T) {
	clientFor := func(payload map[string]any) *Client {
		client, err := NewClient(Config{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return encryptedHTTPResponse(t, payload), nil
		})}, BootstrapBase: "https://api.example", AllowedAPIHosts: []string{"api.example"}})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	base := mustBase(t, "https://api.example")
	input := EmailLogin{Account: "a@example.test", Password: "password", InstallationID: "install", OSVersion: "test"}
	if _, err := clientFor(map[string]any{"status": 0, "msg": nil, "fields": nil}).loginAt(context.Background(), base, input); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("null-field login rejection = %v", err)
	}
	if _, err := clientFor(map[string]any{"status": 0, "msg": nil, "fields": nil}).FetchAuthority(context.Background(), LoginSession{UserID: 1, Token: "token", APIBase: base}); !errors.Is(err, ErrBusinessStatus) {
		t.Fatalf("null-field authority status = %v", err)
	}
	if _, err := clientFor(map[string]any{"status": 1, "msg": nil, "fields": nil}).loginAt(context.Background(), base, input); !errors.Is(err, ErrSchema) {
		t.Fatalf("successful null-field login = %v, want ErrSchema", err)
	}
}

func TestNumericUserIDIsPreservedOnAuthorityAndLines(t *testing.T) {
	const userID = int32(2147483647)
	authKey, err := AuthorityCodec().EncodeJSON(map[string]any{"userId": userID, "encryptKey": "tunnel", "encryptType": "aes-256-cfb", "orderId": "order", "partnerKey": nil, "partnerStatus": 1, "createdTime": 1720000000})
	if err != nil {
		t.Fatal(err)
	}
	requests := make(map[string]json.RawMessage)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		encoded, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		plain, err := NormalCodec().Decode(encoded)
		if err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(plain, &fields); err != nil {
			return nil, err
		}
		switch request.URL.Path {
		case "/v4/user/login.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": nil, "fields": map[string]any{"token": "login", "userId": userID}}), nil
		case "/v4/invpn/getAuthority.do":
			requests[request.URL.Path] = fields["userId"]
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": "provider"})), nil
		case "/v4/invpn/getLines.do":
			requests[request.URL.Path] = fields["userId"]
			return encryptedHTTPResponse(t, envelope(liveShapeLineFields())), nil
		default:
			return nil, errors.New("unexpected route")
		}
	})
	client, err := NewClient(Config{httpClient: &http.Client{Transport: transport}, BootstrapBase: "https://api.example", AllowedAPIHosts: []string{"api.example"}})
	if err != nil {
		t.Fatal(err)
	}
	base := mustBase(t, "https://api.example")
	session, err := client.loginAt(context.Background(), base, EmailLogin{Account: "a@example.test", Password: "password", InstallationID: "install", OSVersion: "test"})
	if err != nil || session.UserID != userID {
		t.Fatalf("numeric login session = %#v, %v", session, err)
	}
	authority, err := client.FetchAuthority(context.Background(), session)
	if err != nil || authority.UserID != "2147483647" {
		t.Fatalf("numeric authority = %#v, %v", authority, err)
	}
	lines, err := client.FetchLines(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines.Lines) != 1 || lines.Lines[0].GroupID != "31" || lines.Lines[0].Label != "上海" {
		t.Fatalf("live lines shape = %#v", lines)
	}
	for route, raw := range requests {
		if string(raw) != "2147483647" {
			t.Fatalf("%s userId wire value = %q, want JSON number", route, raw)
		}
	}
}

func TestUserIDParserRejectsNonIntegerAndOutOfRangeValues(t *testing.T) {
	for _, raw := range []string{"0", "-1", "1.0", "1e3", "+1", "2147483648", "9223372036854775808"} {
		if _, err := requiredPositiveInt32(map[string]json.RawMessage{"userId": json.RawMessage(raw)}, "userId"); !errors.Is(err, ErrSchema) {
			t.Fatalf("userId %q error = %v", raw, err)
		}
	}
	if _, err := requiredPositiveInt32(map[string]json.RawMessage{"userId": json.RawMessage(`"1"`)}, "userId"); !errors.Is(err, ErrSchema) {
		t.Fatalf("string login userId error = %v", err)
	}
	if userID, err := parsePositiveInt32(json.RawMessage(`"1"`), true); err != nil || userID != 1 {
		t.Fatalf("string decrypted authority userId = %d, %v", userID, err)
	}
	if userID, err := parsePositiveInt32(json.RawMessage("2147483647"), true); err != nil || userID != 2147483647 {
		t.Fatalf("numeric authority userId = %d, %v", userID, err)
	}
}

func liveShapeLineFields() map[string]any {
	return map[string]any{
		"groups": []any{map[string]any{"id": 31, "name": "Live Group"}},
		"lines": []any{map[string]any{
			"host": "node.example", "port": 11000, "provider": "WIFIIN", "groupId": 31,
			"lineName": []any{map[string]any{"language": "en-US", "name": "Shanghai"}, map[string]any{"language": "zh-CN", "name": "上海"}}, "mode": 2, "weight": 7, "auto": true,
		}},
	}
}

func TestLocalizedLineNamePreferenceFallbackAndBounds(t *testing.T) {
	base := map[string]any{"host": "node.example", "port": 11000, "provider": "WIFIIN", "groupId": "g"}
	withNames := func(lineName any) map[string]json.RawMessage {
		line := make(map[string]any, len(base)+1)
		for key, value := range base {
			line[key] = value
		}
		line["lineName"] = lineName
		return rawLineFields(t, []any{map[string]any{"id": "g"}}, []any{line})
	}
	name := []any{
		map[string]any{"language": "en-US", "name": "Tokyo"},
		map[string]any{"language": "zh-CN", "name": "东京"},
	}
	lines, err := validateLines(withNames(name))
	if err != nil || len(lines.Lines) != 1 || lines.Lines[0].Label != "东京" {
		t.Fatalf("zh-CN localized label = %#v, %v", lines, err)
	}
	lines, err = validateLinesForLanguage(withNames(name), "en-US")
	if err != nil || len(lines.Lines) != 1 || lines.Lines[0].Label != "Tokyo" {
		t.Fatalf("en-US localized label = %#v, %v", lines, err)
	}
	lines, err = validateLines(withNames([]any{map[string]any{"language": "en-US", "name": "Tokyo"}}))
	if err != nil || lines.Lines[0].Label != "Tokyo" {
		t.Fatalf("first non-empty localized fallback = %#v, %v", lines, err)
	}
	descending := make(map[string]any, len(base)+1)
	for key, value := range base {
		descending[key] = value
	}
	descending["desc"] = "Fallback description"
	lines, err = validateLines(rawLineFields(t, []any{map[string]any{"id": "g"}}, []any{descending}))
	if err != nil || lines.Lines[0].Label != "Fallback description" {
		t.Fatalf("description fallback = %#v, %v", lines, err)
	}
	oversized := make([]any, maxLocalizedNameEntries+1)
	for index := range oversized {
		oversized[index] = map[string]any{"language": "en-US", "name": "name"}
	}
	for _, malformed := range []any{
		"not an array",
		[]any{},
		oversized,
		[]any{map[string]any{"language": strings.Repeat("l", maxLocaleBytes+1), "name": "name"}},
		[]any{map[string]any{"language": "en-US", "name": strings.Repeat("n", maxLineMetadataBytes+1)}},
		[]any{map[string]any{"language": "en-US"}},
		[]any{map[string]any{"language": "en-US", "name": "name", "one": 1, "two": 2, "three": 3}},
	} {
		if _, err := validateLines(withNames(malformed)); !errors.Is(err, ErrInvalidLine) {
			t.Fatalf("malformed lineName %#v error = %v", malformed, err)
		}
	}
}

func TestLineSchemaCaps(t *testing.T) {
	groupsAtLimit := make([]any, maxGroups)
	for index := range groupsAtLimit {
		groupsAtLimit[index] = map[string]any{"id": "g" + strconv.Itoa(index), "name": strings.Repeat("n", maxLineMetadataBytes)}
	}
	if lines, err := validateLines(rawLineFields(t, groupsAtLimit, []any{})); err != nil || len(lines.Groups) != maxGroups {
		t.Fatalf("group boundary = (%d groups, %v)", len(lines.Groups), err)
	}
	if _, err := validateLines(rawLineFields(t, append(groupsAtLimit, map[string]any{"id": "over"}), []any{})); !errors.Is(err, ErrSchema) {
		t.Fatalf("over-cap groups error = %v", err)
	}

	validLine := map[string]any{"host": "node.example", "port": 11000, "provider": "WIFIIN", "groupId": "g", "desc": strings.Repeat("x", maxLineMetadataBytes), "groupName": strings.Repeat("x", maxLineMetadataBytes), "model": strings.Repeat("x", maxLineMetadataBytes)}
	linesAtLimit := make([]any, maxLines)
	for index := range linesAtLimit {
		linesAtLimit[index] = validLine
	}
	if lines, err := validateLines(rawLineFields(t, []any{map[string]any{"id": "g"}}, linesAtLimit)); err != nil || len(lines.Lines) != maxLines {
		t.Fatalf("line boundary = (%d lines, %v)", len(lines.Lines), err)
	}
	if _, err := validateLines(rawLineFields(t, []any{map[string]any{"id": "g"}}, append(linesAtLimit, validLine))); !errors.Is(err, ErrSchema) {
		t.Fatalf("over-cap lines error = %v", err)
	}
	for _, field := range []string{"desc", "groupName", "model"} {
		over := make(map[string]any, len(validLine)+1)
		for name, value := range validLine {
			over[name] = value
		}
		over[field] = strings.Repeat("x", maxLineMetadataBytes+1)
		if _, err := validateLines(rawLineFields(t, []any{map[string]any{"id": "g"}}, []any{over})); !errors.Is(err, ErrInvalidLine) {
			t.Fatalf("over-cap %s error = %v", field, err)
		}
	}
	if _, err := validateLines(rawLineFields(t, []any{map[string]any{"id": strings.Repeat("g", maxGroupIDBytes+1)}}, []any{})); !errors.Is(err, ErrInvalidLine) {
		t.Fatalf("over-cap group ID error = %v", err)
	}
}

func TestControlSecretAndAccountStringCaps(t *testing.T) {
	if _, err := BuildEmailLoginFields(EmailLogin{Account: strings.Repeat("a", maxControlFieldBytes+1), Password: "p", InstallationID: "id"}, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrInvalidVerifyInput) {
		t.Fatalf("over-cap account error = %v", err)
	}
	if _, err := BuildEmailLoginFields(EmailLogin{Account: "a@example.test", Password: strings.Repeat("p", maxControlFieldBytes+1), InstallationID: "id"}, "20260715101112123", bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrInvalidVerifyInput) {
		t.Fatalf("over-cap password error = %v", err)
	}
	if _, err := requiredString(map[string]json.RawMessage{"token": json.RawMessage(strconv.Quote(strings.Repeat("t", maxControlFieldBytes+1)))}, "token"); !errors.Is(err, ErrSchema) {
		t.Fatalf("over-cap token error = %v", err)
	}
	if authorityKeyWithinLimit(authorityKey{UserID: json.RawMessage("1"), OrderID: "o", EncryptKey: strings.Repeat("k", maxControlFieldBytes+1), EncryptType: "aes-256-cfb"}) {
		t.Fatal("over-cap authority key accepted")
	}
}

func rawLineFields(t *testing.T, groups, lines []any) map[string]json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"groups": groups, "lines": lines})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func mustBase(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type stringReader string

func (r stringReader) Read(data []byte) (int, error) {
	if len(r) == 0 {
		return 0, io.EOF
	}
	count := copy(data, r)
	return count, io.EOF
}
