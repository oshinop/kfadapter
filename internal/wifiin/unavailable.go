package wifiin

// UDPEnabled reports whether the production WIFIIN UDP path is enabled. It is
// intentionally constant false until a controlled live fixture verifies the
// upstream protocol and explicit feature-gate work is reviewed.
func UDPEnabled() bool { return false }
