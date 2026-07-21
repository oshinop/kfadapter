package kuaifan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIHost = "ws.kuaifan.co"
	defaultAPIBase = "https://" + defaultAPIHost

	maxControlFieldBytes     = 4096
	maxResponseFields        = 128
	maxAuthorityAuthKeyBytes = 8192
	maxGroups                = 512
	maxLines                 = 4096
	maxGroupIDBytes          = 128
	maxLineMetadataBytes     = 256
	maxGroupObjectFields     = 16
	maxLineObjectFields      = 32
	maxLocalizedNameEntries  = 8
	maxLocalizedNameFields   = 4
	maxLocaleBytes           = 32
	maxUnixMilli             = int64(253402300799999)
)

var (
	ErrUnapprovedAPIBase = errors.New("control: API base is not approved HTTPS")
	ErrInsecureTLS       = errors.New("control: insecure TLS transport")
	ErrHTTPStatus        = errors.New("control: unexpected HTTP status")
	ErrBusinessStatus    = errors.New("control: unexpected business status")
	ErrLoginRejected     = errors.New("control: login rejected")
	ErrSchema            = errors.New("control: response schema is invalid")
	ErrUnsupportedCipher = errors.New("control: unsupported authority cipher")
	ErrInvalidLine       = errors.New("control: invalid line")
)

// Config configures a HTTPS-only control-plane client. AllowedAPIHosts is an
// administrator-controlled hostname allowlist. An empty list permits only the
// documented bootstrap host.
type Config struct {
	AllowedAPIHosts []string
	BootstrapBase   string
	Language        string
	Location        *time.Location
	Clock           func() time.Time
	Random          io.Reader
	RequestTimeout  time.Duration

	// httpClient is available only to same-package behavioral tests. Production
	// callers always receive a dedicated TLS-validating client.
	httpClient *http.Client
}

// Client sends encrypted requests and validates every response according to
// one immutable provider profile. It contains no account, token, or authority
// state.
type Client struct {
	profile        providerProfile
	httpClient     *http.Client
	allowedHosts   map[string]struct{}
	bootstrapBase  *url.URL
	language       string
	location       *time.Location
	clock          func() time.Time
	random         io.Reader
	requestTimeout time.Duration
	normalCodec    Codec
	authorityCodec Codec
}

// lockedReader permits concurrent authority and line requests to share an
// injected entropy source safely. crypto/rand.Reader is safe already, but
// callers may supply a deterministic fixture reader.
type lockedReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func (r *lockedReader) Read(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reader.Read(data)
}

// NewIOSClient creates an iOS control-profile client.
func NewIOSClient(cfg Config) (*Client, error) { return newClient(cfg, iosClientProfile{}) }

// NewWindowsClient creates a Windows control-profile client.
func NewWindowsClient(cfg Config) (*Client, error) { return newClient(cfg, windowsClientProfile{}) }

func newClient(cfg Config, profile providerProfile) (*Client, error) {
	allowed, err := normalizedAllowlist(cfg.AllowedAPIHosts)
	if err != nil {
		return nil, err
	}
	bootstrap := cfg.BootstrapBase
	if bootstrap == "" {
		bootstrap = defaultAPIBase
	}
	base, err := parseApprovedBase(bootstrap, allowed)
	if err != nil {
		return nil, err
	}
	client := cfg.httpClient
	if client == nil {
		client = hardenedHTTPClient()
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrInsecureTLS
	}
	// Redirects would otherwise let a valid approved initial URL cross the
	// HTTPS/allowlist boundary. A copy avoids changing a caller-owned client.
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	language := cfg.Language
	if language == "" {
		language = "zh-CN"
	}
	location := cfg.Location
	if location == nil {
		location = time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	randomness := cfg.Random
	if randomness == nil {
		randomness = rand.Reader
	}
	randomness = &lockedReader{reader: randomness}
	deadline := cfg.RequestTimeout
	if deadline <= 0 || deadline > 15*time.Second {
		deadline = 15 * time.Second
	}
	return &Client{
		profile:        profile,
		httpClient:     &clone,
		allowedHosts:   allowed,
		bootstrapBase:  base,
		language:       language,
		location:       location,
		clock:          clock,
		random:         randomness,
		requestTimeout: deadline,
		normalCodec:    NormalCodec(),
		authorityCodec: AuthorityCodec(),
	}, nil
}

func hardenedHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{Transport: &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}}
}

// APIBase validates a remotely supplied control endpoint against the configured
// HTTPS hostname allowlist.
func (c *Client) APIBase(raw string) (*url.URL, error) {
	return parseApprovedBase(raw, c.allowedHosts)
}

// ClientConfig is the validated result of client/conf.do.
type ClientConfig struct {
	APIBase *url.URL
}

// FetchClientConfig obtains client configuration from the fixed bootstrap host.
// An absent or unapproved replacement is deliberately ignored in favor of the
// documented bootstrap API base.
func (c *Client) FetchClientConfig(ctx context.Context) (ClientConfig, error) {
	response, err := c.post(ctx, c.bootstrapBase, "/v4/client/conf.do", c.profile.configFields())
	if err != nil {
		return ClientConfig{}, err
	}
	if *response.Status != 1 {
		return ClientConfig{}, businessStatus(*response.Status)
	}
	base := cloneURL(c.bootstrapBase)
	if domain, ok := optionalNestedString(response.Fields, "domain", "ws"); ok && domain != "" {
		// Some observed config responses carry a host rather than a full URL;
		// construct HTTPS explicitly before applying the administrator allowlist.
		if !strings.Contains(domain, "://") {
			domain = "https://" + domain
		}
		if candidate, err := c.APIBase(domain); err == nil {
			base = candidate
		}
	}
	return ClientConfig{APIBase: base}, nil
}

// FetchConfig is retained as a concise synonym for FetchClientConfig.
func (c *Client) FetchConfig(ctx context.Context) (ClientConfig, error) {
	return c.FetchClientConfig(ctx)
}

// AccountProfile is the account metadata validated by user/refresh.do.
type AccountProfile struct {
	IsVIP     bool
	VIPEndsAt time.Time
}

// LoginSession is provisional credential material. It is kept only in memory
// and must be refreshed before authority and line retrieval.
type LoginSession struct {
	UserID  int32
	Token   string
	APIBase *url.URL
	Profile AccountProfile
}

// Login performs configuration selection and then the email/password login.
// A rejected login is returned as ErrLoginRejected and is never retried here.
func (c *Client) Login(ctx context.Context, input EmailLogin) (LoginSession, error) {
	configuration, err := c.FetchClientConfig(ctx)
	if err != nil {
		return LoginSession{}, err
	}
	return c.loginAt(ctx, configuration.APIBase, input)
}

func (c *Client) loginAt(ctx context.Context, base *url.URL, input EmailLogin) (LoginSession, error) {
	return c.profile.login(ctx, c, base, input)
}

// RefreshSession validates the login token against user/refresh.do, accepts a
// rotated token, and captures the authoritative VIP profile. The response must
// remain bound to the same user before any authority or line request is sent.
func (c *Client) RefreshSession(ctx context.Context, session LoginSession) (LoginSession, error) {
	return c.profile.refresh(ctx, c, session)
}

// Authority is the independently validated authority response. No caller
// should serialize or log this value; it includes tunnel material by necessity.
type Authority struct {
	UserID            string
	OrderID           string
	EncryptKey        string
	EncryptType       string
	ProviderToken     string
	ProviderExtension string
}

// FetchAuthority obtains and decrypts authority using the login token. The
// returned provider token stays distinct from LoginSession.Token.
func (c *Client) FetchAuthority(ctx context.Context, session LoginSession) (Authority, error) {
	return c.profile.fetchAuthority(ctx, c, session)
}

type authorityKey struct {
	UserID      json.RawMessage `json:"userId"`
	EncryptKey  string          `json:"encryptKey"`
	EncryptType string          `json:"encryptType"`
	OrderID     string          `json:"orderId"`
}

// Group is a validated server-defined line group.
type Group struct {
	ID   string
	Name string
}

// Line is a validated provider endpoint. Eligibility is profile-specific: the
// baseline tunnel supports WIFIIN while recovered WS rows remain metadata only.
type Line struct {
	Label     string
	Host      string
	Port      uint16
	Provider  string
	GroupID   string
	GroupName string
	Model     string
	Weight    int
	Auto      bool
	Eligible  bool
}

// Lines is the validated result of getLines.do.
type Lines struct {
	Groups []Group
	Lines  []Line
}

// FetchLines uses the login token (not the authority provider token).
func (c *Client) FetchLines(ctx context.Context, session LoginSession) (Lines, error) {
	return c.profile.fetchLines(ctx, c, session)
}

type responseEnvelope struct {
	Status *int                       `json:"status"`
	Msg    *string                    `json:"msg"`
	Fields map[string]json.RawMessage `json:"fields"`
}

type httpStatusError struct{ status int }

func (err *httpStatusError) Error() string {
	return fmt.Sprintf("control: unexpected HTTP status %d", err.status)
}

func (err *httpStatusError) Unwrap() error { return ErrHTTPStatus }

func (c *Client) post(ctx context.Context, base *url.URL, route string, fields any) (responseEnvelope, error) {
	if base == nil {
		return responseEnvelope{}, ErrUnapprovedAPIBase
	}
	if _, err := parseApprovedBase(base.String(), c.allowedHosts); err != nil {
		return responseEnvelope{}, err
	}
	payload, err := requestEnvelope(fields, c.language, c.timestamp(), c.random)
	if err != nil {
		return responseEnvelope{}, err
	}
	body, err := c.normalCodec.EncodeJSON(payload)
	if err != nil {
		return responseEnvelope{}, err
	}
	endpoint := base.ResolveReference(&url.URL{Path: route})
	requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return responseEnvelope{}, fmt.Errorf("control: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; UTF-8")
	req.Header.Set("User-Agent", c.profile.userAgent())
	response, err := c.httpClient.Do(req)
	if err != nil {
		return responseEnvelope{}, fmt.Errorf("control: request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseEnvelope{}, &httpStatusError{status: response.StatusCode}
	}
	if response.ContentLength > int64(base64MaximumEncodedSize()) {
		return responseEnvelope{}, ErrResponseTooLarge
	}
	encoded, err := readBounded(response.Body, base64MaximumEncodedSize())
	if err != nil {
		return responseEnvelope{}, err
	}
	var envelope responseEnvelope
	if err := c.normalCodec.DecodeJSON(encoded, &envelope); err != nil {
		return responseEnvelope{}, fmt.Errorf("%w: decode response: %w", ErrInvalidEnvelope, err)
	}
	if envelope.Status == nil || len(envelope.Fields) > maxResponseFields || (envelope.Msg != nil && !withinLimit(*envelope.Msg, maxControlFieldBytes)) {
		return responseEnvelope{}, ErrInvalidEnvelope
	}
	return envelope, nil
}

func requestEnvelope(fields any, language, timestamp string, randomness io.Reader) (map[string]any, error) {
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("control: marshal request fields: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil || payload == nil {
		return nil, fmt.Errorf("control: request fields must be an object: %w", err)
	}
	payload["lang"] = language
	nonce, err := wireprofile.RandomInt(randomness, 100000000)
	if err != nil {
		return nil, fmt.Errorf("control: nonce: %w", err)
	}
	payload["nonce"] = fmt.Sprintf("%08d", nonce)
	if _, hasTime := payload["time"]; !hasTime {
		payload["time"] = timestamp
	}
	return payload, nil
}

func (c *Client) timestamp() string {
	now := c.clock().In(c.location)
	return now.Format("20060102150405") + fmt.Sprintf("%03d", now.Nanosecond()/int(time.Millisecond))
}

func (c *Client) validateSession(session LoginSession) error {
	if session.UserID <= 0 || session.Token == "" || session.APIBase == nil || !withinLimit(session.Token, maxControlFieldBytes) {
		return ErrSchema
	}
	_, err := parseApprovedBase(session.APIBase.String(), c.allowedHosts)
	return err
}

func normalizedAllowlist(input []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(input))
	if len(input) == 0 {
		allowed[defaultAPIHost] = struct{}{}
	}
	for _, candidate := range input {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, "://") {
			parsed, err := url.Parse(candidate)
			if err != nil || parsed.Hostname() == "" || parsed.Scheme != "https" || parsed.User != nil {
				return nil, ErrUnapprovedAPIBase
			}
			candidate = parsed.Hostname()
		}
		candidate = strings.ToLower(strings.TrimSuffix(candidate, "."))
		if candidate == "" || strings.ContainsAny(candidate, "/?#@") {
			return nil, ErrUnapprovedAPIBase
		}
		allowed[candidate] = struct{}{}
	}
	return allowed, nil
}

func parseApprovedBase(raw string, allowed map[string]struct{}) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrUnapprovedAPIBase
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, ErrUnapprovedAPIBase
	}
	port := parsed.Port()
	if (port != "" || strings.HasSuffix(parsed.Host, ":")) && !isCanonicalURLPort(port) {
		return nil, ErrUnapprovedAPIBase
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if _, ok := allowed[host]; !ok {
		return nil, ErrUnapprovedAPIBase
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed, nil
}

func isCanonicalURLPort(port string) bool {
	if len(port) == 0 || (len(port) > 1 && port[0] == '0') {
		return false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	return err == nil && parsedPort > 0
}

func cloneURL(in *url.URL) *url.URL {
	out := *in
	return &out
}

func base64MaximumEncodedSize() int { return 4 * ((MaxPlaintextBytes + blockSize + 2) / 3) }

func readBounded(reader io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("control: read response: %w", err)
	}
	if len(data) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func businessStatus(status int) error { return fmt.Errorf("%w: %d", ErrBusinessStatus, status) }

func requiredString(fields map[string]json.RawMessage, name string) (string, error) {
	return requiredStringLimit(fields, name, maxControlFieldBytes)
}

func requiredStringLimit(fields map[string]json.RawMessage, name string, limit int) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", ErrSchema
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" || !withinLimit(value, limit) {
		return "", ErrSchema
	}
	return value, nil
}

func requiredPositiveInt32(fields map[string]json.RawMessage, name string) (int32, error) {
	raw, ok := fields[name]
	if !ok {
		return 0, ErrSchema
	}
	return parsePositiveInt32(raw, false)
}

func requiredBool(fields map[string]json.RawMessage, name string) (bool, error) {
	raw, ok := fields[name]
	if !ok {
		return false, ErrSchema
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, ErrSchema
	}
	return value, nil
}

func requiredUnixMilli(fields map[string]json.RawMessage, name string) (time.Time, error) {
	raw, ok := fields[name]
	if !ok {
		return time.Time{}, ErrSchema
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value < 0 || value > maxUnixMilli {
		return time.Time{}, ErrSchema
	}
	if value == 0 {
		return time.Time{}, nil
	}
	return time.UnixMilli(value).UTC(), nil
}

// parsePositiveInt32 accepts only a JSON number for login identifiers. Decrypted
// authority material may encode the same identifier as a JSON string.
func parsePositiveInt32(raw json.RawMessage, allowString bool) (int32, error) {
	if allowString {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			return parsePositiveDecimal(text)
		}
	}
	return parsePositiveDecimal(string(raw))
}

func parsePositiveDecimal(value string) (int32, error) {
	if value == "" || !withinLimit(value, maxControlFieldBytes) {
		return 0, ErrSchema
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, ErrSchema
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed <= 0 {
		return 0, ErrSchema
	}
	return int32(parsed), nil
}

func formatUserID(userID int32) string { return strconv.FormatInt(int64(userID), 10) }

func authorityKeyWithinLimit(key authorityKey) bool {
	_, err := parsePositiveInt32(key.UserID, true)
	return err == nil &&
		withinLimit(key.EncryptKey, maxControlFieldBytes) &&
		withinLimit(key.EncryptType, maxControlFieldBytes) &&
		withinLimit(key.OrderID, maxControlFieldBytes)
}

func withinLimit(value string, limit int) bool { return len(value) <= limit }

func buildProviderExtension(providerToken, orderID, userID string) (string, error) {
	for _, field := range []string{providerToken, orderID, userID} {
		if !validProviderExtensionField(field) {
			return "", ErrSchema
		}
	}
	return "|" + providerToken + "|" + wireprofile.IOSPackageName + "|" + orderID + "|" + userID + "|" + wireprofile.IOSProviderDevice + "|" + wireprofile.IOSProviderVersion, nil
}

func validProviderExtensionField(value string) bool {
	if value == "" || !withinLimit(value, maxControlFieldBytes) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x21 || character > 0x7e || character == '|' {
			return false
		}
	}
	return true
}

func optionalNestedString(fields map[string]json.RawMessage, outer, inner string) (string, bool) {
	raw, ok := fields[outer]
	if !ok {
		return "", false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return "", false
	}
	raw, ok = object[inner]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || !withinLimit(value, maxControlFieldBytes) {
		return "", false
	}
	return value, true
}

func validateLines(fields map[string]json.RawMessage) (Lines, error) {
	return validateLinesForLanguage(fields, "zh-CN")
}

func validateLinesForLanguage(fields map[string]json.RawMessage, language string) (Lines, error) {
	return validateLinesForProfile(fields, language, iosClientProfile{})
}

func validateLinesForProfile(fields map[string]json.RawMessage, language string, profile providerProfile) (Lines, error) {
	rawGroups, ok := fields["groups"]
	if !ok {
		return Lines{}, ErrSchema
	}
	rawLines, ok := fields["lines"]
	if !ok {
		return Lines{}, ErrSchema
	}
	var groupObjects []map[string]json.RawMessage
	var lineObjects []map[string]json.RawMessage
	if err := json.Unmarshal(rawGroups, &groupObjects); err != nil || groupObjects == nil || len(groupObjects) > maxGroups {
		return Lines{}, ErrSchema
	}
	if err := json.Unmarshal(rawLines, &lineObjects); err != nil || lineObjects == nil || len(lineObjects) > maxLines {
		return Lines{}, ErrSchema
	}
	groups := make([]Group, 0, len(groupObjects))
	groupIDs := make(map[string]struct{}, len(groupObjects))
	for _, object := range groupObjects {
		if len(object) > maxGroupObjectFields {
			return Lines{}, ErrSchema
		}
		id, found := objectID(object, "id", "groupId")
		if !found || !withinLimit(id, maxGroupIDBytes) {
			return Lines{}, ErrInvalidLine
		}
		if _, duplicate := groupIDs[id]; duplicate {
			return Lines{}, ErrInvalidLine
		}
		name, _, err := optionalStringLimit(object, maxLineMetadataBytes, "name", "groupName", "text")
		if err != nil {
			return Lines{}, err
		}
		groupIDs[id] = struct{}{}
		groups = append(groups, Group{ID: id, Name: name})
	}
	lines := make([]Line, 0, len(lineObjects))
	for _, object := range lineObjects {
		line, err := parseLine(object, groupIDs, language, profile)
		if err != nil {
			return Lines{}, err
		}
		lines = append(lines, line)
	}
	return Lines{Groups: groups, Lines: lines}, nil
}

func parseLine(object map[string]json.RawMessage, groupIDs map[string]struct{}, language string, profile providerProfile) (Line, error) {
	if len(object) > maxLineObjectFields {
		return Line{}, ErrSchema
	}
	host, _, err := optionalStringLimit(object, 253, "host")
	if err != nil || !validHost(host) {
		return Line{}, ErrInvalidLine
	}
	provider, _, err := optionalStringLimit(object, maxLineMetadataBytes, "provider")
	if err != nil {
		return Line{}, ErrInvalidLine
	}
	eligible, err := profile.validateLine(object, provider)
	if err != nil {
		return Line{}, err
	}
	groupID, found := objectID(object, "groupId")
	if !found || !withinLimit(groupID, maxGroupIDBytes) {
		return Line{}, ErrInvalidLine
	}
	if _, exists := groupIDs[groupID]; !exists {
		return Line{}, ErrInvalidLine
	}
	port, ok := portValue(object["port"])
	if !ok {
		return Line{}, ErrInvalidLine
	}
	label, hasLocalizedName, err := localizedLineName(object, language)
	if err != nil {
		return Line{}, err
	}
	if !hasLocalizedName {
		label, _, err = optionalStringLimit(object, maxLineMetadataBytes, "desc")
		if err != nil {
			return Line{}, err
		}
	}
	groupName, _, err := optionalStringLimit(object, maxLineMetadataBytes, "groupName")
	if err != nil {
		return Line{}, err
	}
	model, _, err := optionalStringLimit(object, maxLineMetadataBytes, "model")
	if err != nil {
		return Line{}, err
	}
	weight, _ := integerValue(object["weight"])
	auto, _ := booleanValue(object["auto"])
	return Line{Label: label, Host: host, Port: port, Provider: provider, GroupID: groupID, GroupName: groupName, Model: model, Weight: weight, Auto: auto, Eligible: eligible}, nil
}

func localizedLineName(object map[string]json.RawMessage, preferredLanguage string) (string, bool, error) {
	raw, exists := object["lineName"]
	if !exists {
		return "", false, nil
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil || len(entries) == 0 || len(entries) > maxLocalizedNameEntries {
		return "", false, ErrInvalidLine
	}
	fallback := ""
	preferred := ""
	preferredLocale := strings.ToLower(strings.ReplaceAll(preferredLanguage, "_", "-"))
	for _, entry := range entries {
		if len(entry) == 0 || len(entry) > maxLocalizedNameFields {
			return "", false, ErrInvalidLine
		}
		languageRaw, ok := entry["language"]
		if !ok {
			return "", false, ErrInvalidLine
		}
		var language string
		if err := json.Unmarshal(languageRaw, &language); err != nil || language == "" || !withinLimit(language, maxLocaleBytes) {
			return "", false, ErrInvalidLine
		}
		nameRaw, ok := entry["name"]
		if !ok {
			return "", false, ErrInvalidLine
		}
		var name string
		if err := json.Unmarshal(nameRaw, &name); err != nil || !withinLimit(name, maxLineMetadataBytes) {
			return "", false, ErrInvalidLine
		}
		if name == "" {
			continue
		}
		if fallback == "" {
			fallback = name
		}
		if strings.ToLower(strings.ReplaceAll(language, "_", "-")) == preferredLocale && preferred == "" {
			preferred = name
		}
	}
	if preferred != "" {
		return preferred, true, nil
	}
	return fallback, true, nil
}

func optionalStringLimit(object map[string]json.RawMessage, limit int, names ...string) (string, bool, error) {
	for _, name := range names {
		raw, exists := object[name]
		if !exists {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || !withinLimit(value, limit) {
			return "", false, ErrInvalidLine
		}
		return value, true, nil
	}
	return "", false, nil
}

func objectID(object map[string]json.RawMessage, names ...string) (string, bool) {
	for _, name := range names {
		raw, exists := object[name]
		if !exists {
			continue
		}
		if value, ok := idValue(raw); ok {
			return value, true
		}
	}
	return "", false
}

func idValue(raw json.RawMessage) (string, bool) {
	var stringValue string
	if json.Unmarshal(raw, &stringValue) == nil && stringValue != "" {
		return stringValue, true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var number json.Number
	if decoder.Decode(&number) == nil {
		if _, err := strconv.ParseInt(number.String(), 10, 64); err == nil {
			return number.String(), true
		}
	}
	return "", false
}

func portValue(raw json.RawMessage) (uint16, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&n); err == nil {
		port, err := strconv.ParseUint(n.String(), 10, 16)
		return uint16(port), err == nil && port != 0
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		port, err := strconv.ParseUint(text, 10, 16)
		return uint16(port), err == nil && port != 0
	}
	return 0, false
}

func integerValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return 0, false
	}
	value, err := strconv.Atoi(number.String())
	return value, err == nil
}

func booleanValue(raw json.RawMessage) (bool, bool) {
	if len(raw) == 0 {
		return false, false
	}
	var value bool
	if json.Unmarshal(raw, &value) == nil {
		return value, true
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) == nil {
		return number.String() == "1", number.String() == "0" || number.String() == "1"
	}
	return false, false
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char == '-' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
				return false
			}
		}
	}
	return true
}
