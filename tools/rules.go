package tools

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

type ListRulesInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"Maximum number of results (1-200, default 100). Use offset to paginate."`
	Offset int `json:"offset,omitempty" jsonschema:"Number of results to skip (default 0)."`
}

const listRulesDesc = `List quarantine rules — blocked binaries and publishers with their scope.

Returns only active deny rules for application launch. Each rule has rule_id, scope, name (absent when the target record is unknown), and one of binary_id / publisher_id:
- "binary": blocks a specific application (identified by binary_id).
- "publisher": blocks all applications from a publisher (publisher_id).
- "all_unsigned": a special rule that blocks ALL unsigned (no code-signing certificate) applications from running. This is the most powerful rule.

Rules that only block an application's network access, and ignore rules, are not listed here; their changes do appear in query_history as AppRuleChanged / PublisherRuleChanged with target Network or Alerts. A rule carries no creation time — date rule changes from those events.

If no rules are returned, nothing is currently quarantined.`

func listRules(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input ListRulesInput
	if err := decode(args, &input); err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))
	return b.Get(ctx, "/api/v1/rules", params)
}
