package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

type ListBinariesInput struct {
	Search         string `json:"search,omitempty" jsonschema:"Text to filter by name, filename, description, or publisher."`
	Limit          int    `json:"limit,omitempty" jsonschema:"Maximum number of results (1-200, default 100). Use offset to paginate."`
	Offset         int    `json:"offset,omitempty" jsonschema:"Number of results to skip for pagination (default 0)."`
	UnsignedOnly   bool   `json:"unsigned_only,omitempty" jsonschema:"If true, return only unsigned binaries (no code-signing publisher). This is the #1 security triage filter."`
	RunningOnly    bool   `json:"running_only,omitempty" jsonschema:"If true, return only binaries that have at least one running process right now."`
	PublisherID    int    `json:"publisher_id,omitempty" jsonschema:"Filter to binaries signed by this specific publisher. Get publisher IDs from list_publishers. Useful to answer 'what binaries does this publisher have on the system?'"`
	FirstSeenAfter int64  `json:"first_seen_after,omitempty" jsonschema:"Timestamp (ms since Unix epoch UTC). Return only binaries first seen after this time. For 'last 24h' use get_stats().current_time - 86400000."`
	LastSeenAfter  int64  `json:"last_seen_after,omitempty" jsonschema:"Timestamp (ms since Unix epoch UTC). Exclude binaries that disappeared before this time. Binaries still active on the system are always included. Use to filter out old/removed software."`
	PathContains   string `json:"path_contains,omitempty" jsonschema:"Case-insensitive substring match on the binary's file path. Use to find binaries in specific locations, e.g. 'Temp', 'Downloads', 'AppData', 'system32'."`
}

const listBinariesDesc = `List tracked binaries with filters — unsigned-only, currently-running, first-seen-after date, path substring, or publisher ID.

Returns binaries with metadata: binary_id, name, filename (the full path), filename_hash, hash_sha256, hash_sha1, description, company, version, original_filename, size, creation_time and modification_time (file timestamps), last_start_time (the last process start), running_process_count, publisher_id with publisher_name (publisher_name is absent when unsigned), last_access_times, and activities. The response's total is the number of matches before offset/limit.

filename_hash groups binaries by file path. Multiple binary records can share the same filename_hash when the file at that path changed over time (e.g., updates). When a new version appears, a new record is created and older records gain a NoLongerSeen timestamp in last_access_times.

GROUPING RECORDS INTO APPLICATIONS. Records are per-version. Group by filename_hash, then confirm filename matches within the group — filename_hash is a hash of the path, so unrelated paths can collide. The current version is the record in the group with no NoLongerSeen; the rest are retired history. There is no filename_hash query filter: to fetch a whole group, pass the full path as path_contains, or group client-side from a broader listing.

MERGING last_access_times ACROSS A GROUP. A replacement record does NOT inherit the old record's timestamps, so per-record values are incomplete for the application. Merge like this:
- Webcam, Mic, Location, Network — take the MAX across the group. This is the real answer to "when did this app last use X". Taking it from the current record alone will read as "never" for any app updated since it last used that resource.
- FirstTimeSeen — take the MIN across the group: when the application first appeared at this path. The current record's own FirstTimeSeen is just when that build appeared.
- LastTimeHashChanged — take the MAX: when the application last changed on disk.
- NoLongerSeen — do NOT merge. It is per-record and marks a retired version. The application is still installed if ANY record in the group lacks it.

last_access_times is an object mapping access types (Webcam, Mic, Location, Network, FirstTimeSeen, NoLongerSeen, LastTimeHashChanged, McpConnection) to epoch-ms timestamps. activities is an array of currently-ongoing access: Webcam, Mic, Location, McpClient.

McpConnection is the last time the binary was identified as the AI agent behind a connection to AppControl's own MCP API — the interface you are using now — and McpClient marks one that is connected at the moment. The client you run in will normally carry both; that is expected and not a finding.

Network is the last time the binary sent or received bytes, and is deliberately coarse: it is only refreshed once per 5 minutes of continuous activity, so it can lag real traffic by up to 5 minutes and must not be read as a precise last-packet time. Its absence means the binary has not been seen using the network since network monitoring began. There is no Network entry in activities — use get_monitoring to see whether an app is transferring right now.

Tip: Unsigned binaries in user-writable paths are highest risk. Binaries with no publisher and a path under Downloads, Temp, or AppData warrant scrutiny.`

func listBinaries(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input ListBinariesInput
	if err := decode(args, &input); err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))
	setStr(params, "search", input.Search)
	setBool(params, "unsigned_only", input.UnsignedOnly)
	setBool(params, "running_only", input.RunningOnly)
	setInt(params, "publisher_id", input.PublisherID)
	setInt64(params, "first_seen_after", input.FirstSeenAfter)
	setInt64(params, "last_seen_after", input.LastSeenAfter)
	setStr(params, "path_contains", input.PathContains)
	return b.Get(ctx, "/api/v1/binaries", params)
}

type GetBinaryInput struct {
	BinaryID  int    `json:"binary_id,omitempty" jsonschema:"A single binary ID to look up."`
	BinaryIDs string `json:"binary_ids,omitempty" jsonschema:"Comma-separated list of binary IDs for batch lookup. E.g. 42,55,103. Returns an array of binary objects. Use this when you have multiple IDs from history events or process listings."`
}

const getBinaryDesc = `Get detailed info for one or more binaries by ID (batch with comma-separated IDs) — path, hashes, publisher, file timestamps, last_access_times (first-seen, resource access), and running process count.

Returns the same binary object as list_binaries (see that tool for the field list and the per-version grouping rules). A single binary_id returns one object, or an error when the ID is unknown. binary_ids returns an array holding only the IDs that exist — unknown IDs are silently omitted, so compare total with the number you sent.

Supports batch mode: pass multiple IDs at once to avoid repeated calls. For example, after query_history returns 20 NewBinarySeen events, pass all their binary_ids here in one call instead of 20 separate calls.`

func getBinary(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input GetBinaryInput
	if err := decode(args, &input); err != nil {
		return "", err
	}
	if input.BinaryIDs != "" {
		params := url.Values{}
		params.Set("ids", input.BinaryIDs)
		return b.Get(ctx, "/api/v1/binaries", params)
	}
	if input.BinaryID != 0 {
		return b.Get(ctx, fmt.Sprintf("/api/v1/binaries/%d", input.BinaryID), nil)
	}
	return "", fmt.Errorf("provide either binary_id or binary_ids")
}
