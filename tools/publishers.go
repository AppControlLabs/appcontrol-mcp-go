package tools

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

type ListPublishersInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"Maximum number of results (1-200, default 100). Use offset to paginate."`
	Offset int `json:"offset,omitempty" jsonschema:"Number of results to skip (default 0)."`
}

const listPublishersDesc = `List code-signing publishers (certificate identities) — publisher ID, name, country, and location.

Publishers sign binaries with their certificate. A quarantine rule on a publisher blocks ALL binaries signed by that publisher. Returns publisher_id, name, country, and location. No per-publisher counts are returned: to count a publisher's binaries call list_binaries with publisher_id and read total; list_rules shows whether a publisher is blocked.`

func listPublishers(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input ListPublishersInput
	if err := decode(args, &input); err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))
	return b.Get(ctx, "/api/v1/publishers", params)
}
