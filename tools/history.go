package tools

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

type QueryHistoryInput struct {
	StartTime    int64  `json:"start_time,omitempty" jsonschema:"Filter events after this time (ms since Unix epoch UTC). For 'last 24h' use get_stats().current_time - 86400000."`
	EndTime      int64  `json:"end_time,omitempty" jsonschema:"Filter events before this time (ms since Unix epoch UTC)."`
	EventType    string `json:"event_type,omitempty" jsonschema:"Filter by one or more event type names (comma-separated). E.g. 'NewBinarySeen,BinaryHashChanged,ThreatDetected,DriverServiceAdded' for a security sweep in a single call. Names the machine does not know are skipped and listed in the response's ignored_event_types; a list naming no known type is an error."`
	BinaryIDs    []int  `json:"binary_ids,omitempty" jsonschema:"Filter to events for specific binaries only. Useful to get the full history of a suspicious binary after initial triage."`
	PublisherIDs []int  `json:"publisher_ids,omitempty" jsonschema:"Filter to events for binaries signed by these publishers. Get publisher IDs from list_publishers."`
	UnsignedOnly bool   `json:"unsigned_only,omitempty" jsonschema:"If true, return only events for unsigned binaries. Combine with event_type for targeted queries like 'new unsigned binaries' (event_type='NewBinarySeen', unsigned_only=true)."`
	BeforeID     int    `json:"before_id,omitempty" jsonschema:"Pagination cursor. Pass the next_before_id value from a previous response to fetch the next page of older events."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of events (1-200, default 100). Use time ranges to narrow results."`
}

const queryHistoryDesc = `Query security event history — binary first-seen events, quarantine blocks, alerts, and process starts. Filterable by event type, time range, and binary ID.

Results are ordered newest-first. Use cursor-based pagination to page through large result sets: the response includes next_before_id — pass it as before_id in the next call to get the next page. All filters are preserved across pages.

Each event has timestamp, event_type, binary_id, parent_binary_id (-1 when there is none), total_processes (only when the binary had running processes at the time), unread (the user has not yet seen it in the AppControl UI), and an inline "binary" summary (name, filename, hash_sha256, publisher_name) so you can triage without extra get_binary calls. Use get_binary only to drill into specific items.

Key event types to investigate:
- BlockProcess: binary denied execution (threat stopped or needs rule update)
- NewBinarySeen: previously unknown executable appeared
- BinaryHashChanged: known binary's hash changed (update or tampering)
- ThreatDetected: behavioral analysis flagged suspicious activity
- DriverServiceAdded: new kernel driver (always investigate)

All event types: TerminateProcess, CreateProcess, NewBinarySeen, BinaryHashChanged, StopService, StartService, BlockProcess, DriverServiceAdded, DriverServiceRemoved, WebcamAccessed, MicAccessed, LocationAccessed, AppRuleChanged, PublisherRuleChanged, ThreatDetected, ComputerIdle, ComputerActive, McpAccessed, TimelinePin, CriticalTemperature, TemperatureRecovered, FirstNetworkAccess, StartupItem, HostsFile, BrowserExtension.

Some events include a "detail" object with supplementary data:
- TerminateProcess: session_length (process lifetime in ms)
- DriverServiceAdded/Removed: name, description, image_path, publisher, is_driver, is_removal, is_svchost_hosted
- ThreatDetected: threat (classification name), is_pup (potentially unwanted program, less severe than malware)
- AppRuleChanged/PublisherRuleChanged: one event per changed action. target (AppLaunch = quarantine, Network = network block, Alerts = ignore, i.e. no events or prompts for the app), action (Deny, DenyInternet for Network, or NotSet when the action was cleared or the rule deleted), publisher_id (0 for an app rule; the event's binary_id is 0 for a publisher rule)
- McpAccessed: connection_type (Direct = the binary connected to the API itself; ViaServer = it launched the AppControl MCP server, whose record is mcp_server_binary_id, with the launch chain in ancestor_chain, nearest parent first), peer_port. The event's binary_id is the agent held responsible. At most one event per agent binary per 4-hour session, and your own client produces them — a steady trickle is normal, not an intrusion.
- CriticalTemperature/TemperatureRecovered: sensor (Cpu or Gpu), gpu_index (the get_hardware gpu_index, for Gpu), temperature_c (at the crossing; the peak, for Recovered), limit_c, and for Recovered duration_s (how long the sensor stayed over the limit)
- StartupItem: change (Added, CommandChanged), kind (RegRun, RegRunOnce, RegRunWow, RegRunOnceWow, PolicyRun, Winlogon, StartupFolder), location, name, user_sid and username (empty = machine-wide), raw_command, resolved_exe, previous_command (CommandChanged only). binary_id is the resolved executable when it is known.
- HostsFile: change (Entries, DataBasePath), path, added_total, removed_total, added and removed (arrays of {address, hostname}, capped — compare with the totals), previous_directory (DataBasePath only)
- BrowserExtension: browser, browser_key, family (chromium, firefox), user_sid, username, profile_dir, profile_name, added_total, grew_total, items (at most 100, each with change (Added, PermissionsGrew), id, name, version, location, sideloaded (not installed from the browser's store — the main risk signal), path, added_permissions)
FirstNetworkAccess and TimelinePin carry no detail. TimelinePin is a marker the user placed on the timeline; it is not security-relevant.`

func queryHistory(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input QueryHistoryInput
	if err := decode(args, &input); err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))
	setInt64(params, "start_time", input.StartTime)
	setInt64(params, "end_time", input.EndTime)
	setStr(params, "event_type", input.EventType)
	setIntSlice(params, "binary_ids", input.BinaryIDs)
	setIntSlice(params, "publisher_ids", input.PublisherIDs)
	setBool(params, "unsigned_only", input.UnsignedOnly)
	setInt(params, "before_id", input.BeforeID)
	return b.Get(ctx, "/api/v1/history", params)
}
