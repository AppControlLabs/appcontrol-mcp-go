package tools

import (
	"context"
	"errors"
	"net/url"
)

// Backend answers one GET against a machine's local MCP API and returns the
// response body. An API failure is an ordinary error; ErrUnavailable means the
// machine could not be asked at all.
type Backend interface {
	Get(ctx context.Context, path string, params url.Values) (string, error)
}

// ErrUnavailable is what a Backend returns when the machine cannot be reached
// (offline, not entitled, not answering), as opposed to an answer from its API.
var ErrUnavailable = errors.New("appcontrol: machine unavailable")
