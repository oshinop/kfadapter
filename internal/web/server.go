package web

import (
	"net"
	"net/http"

	"golang.org/x/net/netutil"
	"time"
)

// NewHTTPServer constructs the production HTTP server around a validated API.
// Regular response writes are bounded. Authenticated SSE handlers explicitly
// refresh and clear per-write deadlines, preserving idle stream lifetime while
// retaining a bound for a blocked client write.
func NewHTTPServer(config Config, dependencies Dependencies) (*http.Server, *API, error) {
	api, err := NewAPI(config, dependencies)
	if err != nil {
		return nil, nil, err
	}
	return &http.Server{
		Addr:              api.config.Listen,
		Handler:           api,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       api.config.ReadTimeout,
		WriteTimeout:      api.config.WriteTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}, api, nil
}

// Listen binds the configured management address. Cmd owns serving and
// shutdown orchestration.
func (a *API) Listen() (net.Listener, error) {
	if a == nil {
		return nil, net.ErrClosed
	}
	listener, err := net.Listen("tcp", a.config.Listen)
	if err != nil {
		return nil, err
	}
	return netutil.LimitListener(listener, a.config.MaxConnections), nil
}
