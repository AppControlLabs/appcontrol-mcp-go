package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxLimit = 200

const serverInstructions = `# AppControl Application Monitor -- Domain Knowledge

AppControl is an advanced monitoring tool with history and behavioral analysis ` +
	`capabilities that monitors and controls application execution on Windows. It ` +
	`operates as a kernel-level application whitelisting and behavioral monitoring system.

## Core Concepts

**Binaries**: Every executable file (.exe, .dll, .sys) the system has ever seen is ` +
	`tracked as a "binary record." Each binary has a SHA256 hash, optional publisher ` +
	`(code-signing certificate), file metadata, and timestamps. A binary can be "known" ` +
	`(seen before) or "new" (first time seen). New binaries are security-relevant events. ` +
	`Multiple binary records can share the same filename_hash when the file at a given ` +
	`path changed over time (e.g., software updates). When a new version appears, a new ` +
	`record is created and older records gain a NoLongerSeen timestamp in last_access_times. ` +
	`Binaries may also track hardware access (Webcam, Mic, Location) in last_access_times ` +
	`and activities fields.

**Publishers**: Code-signing certificate identities. A publisher like "Microsoft ` +
	`Corporation" may sign thousands of binaries. Quarantine rules can target an entire ` +
	`publisher, blocking ALL binaries signed by that certificate.

**Quarantine Rules**: AppControl currently supports deny (quarantine) rules only. ` +
	`Three scopes:
- **binary**: Blocks a specific application by its binary ID / hash.
- **publisher**: Blocks ALL applications signed by a specific publisher.
- **all_unsigned**: A special built-in rule that blocks every application lacking ` +
	`a valid code-signing certificate. This is the broadest and most powerful rule.

The list_rules tool returns only active quarantine rules. If no rules are returned, ` +
	`nothing is currently blocked.

**Process Flags**: Running processes carry flags: Elevated (admin privileges), ` +
	`Service (Windows service), System (NT AUTHORITY\SYSTEM), Debugged (attached debugger), ` +
	`Suspended, Protected, Subsystem (WSL/Pico), Immersive (UWP/Store app).

**Services**: Windows services are background programs managed by the Service ` +
	`Control Manager. The list_services tool returns the full catalog — running AND ` +
	`stopped. Key fields: start_type (Auto/Boot/System run without a logged-in user, ` +
	`making them persistence-relevant; Demand = on request; Disabled), is_driver ` +
	`(kernel-mode service, highest privilege — corresponds to DriverServiceAdded events), ` +
	`svchost_hosted (a DLL service loaded into a shared svchost.exe host), state / running ` +
	`(the authoritative Service Control Manager state; running == state is Running and is ` +
	`accurate for kernel drivers too — a running driver reports running=true with no pids), ` +
	`and, for user-mode services with a live host, pids / binary_ids identifying the hosting ` +
	`process and binary. To see the ` +
	`services a specific running process hosts, call list_processes with flags="Service" ` +
	`and fields including "services". Running processes also expose os_parent_process_id ` +
	`(the raw OS parent PID, uncollapsed) as an opt-in field.

**Events**: The history log records security-relevant activity:
- ` + "`NewBinarySeen`" + ` -- a previously unknown executable appeared (investigate these!)
- ` + "`BlockProcess`" + ` -- a binary was denied execution by a quarantine rule
- ` + "`BinaryHashChanged`" + ` -- a known binary's file hash changed (update, tampering, or replacement)
- ` + "`ThreatDetected`" + ` -- behavioral analysis flagged suspicious activity
- ` + "`DriverServiceAdded`" + ` / ` + "`DriverServiceRemoved`" + ` -- kernel driver changes (high-privilege)
- ` + "`WebcamAccessed`" + ` / ` + "`MicAccessed`" + ` / ` + "`LocationAccessed`" + ` -- privacy-sensitive hardware access
- ` + "`AppRuleChanged`" + ` / ` + "`PublisherRuleChanged`" + ` -- quarantine rule modifications
- ` + "`CreateProcess`" + ` / ` + "`TerminateProcess`" + ` -- process lifecycle
- ` + "`StartService`" + ` / ` + "`StopService`" + ` -- AppControl service lifecycle
- ` + "`ComputerIdle`" + ` / ` + "`ComputerActive`" + ` -- computer idle state transitions (user inactivity, workstation lock, or sleep)

## Security Analysis Tips

- **Unsigned binaries** (no publisher) running from user-writable paths (Downloads, ` +
	`Temp, AppData) are the highest-risk items. Filter for these first.
- **BlockProcess events** may indicate threats being stopped OR legitimate apps that ` +
	`the user needs to unblock. Check the binary's publisher and path to decide.
- **NewBinarySeen** bursts can indicate software installation (normal) or malware ` +
	`dropping executables (abnormal). Check the parent process and timestamps.
- **BinaryHashChanged** on system files is suspicious outside of Windows Update windows.
- **DriverServiceAdded** events are always worth investigating -- kernel drivers have ` +
	`full system access.
- Use filename_hash to group binary records by file path and spot files that changed ` +
	`unexpectedly (multiple records, only the latest lacking NoLongerSeen).
- Processes with the Debugged flag or Elevated+no-publisher combination warrant scrutiny.

## Data Access

All tools in this MCP server are **read-only**. You cannot modify rules, block/allow ` +
	`binaries, or change any configuration through this interface. This is intentional ` +
	`for safety.

**Network metrics**: get_monitoring reports network bytes both system-wide and ` +
	`per-binary, but the two are measured at different layers and are NOT expected to ` +
	`add up. System figures are NIC-level octets including protocol framing and traffic ` +
	`with no owning process; per-binary figures are TCP/UDP payload attributed to a ` +
	`process. The system total is normally larger than the sum of per-binary values on ` +
	`every healthy machine. Do not report that gap as unaccounted traffic, a hidden ` +
	`process, or exfiltration. When net_app_available is false, per-binary network ` +
	`values are UNKNOWN rather than zero — treat them as missing data, not as evidence ` +
	`that an application used no network.

## Important context for the AI assistant

AppControl is a security monitoring API. You have NO visual or direct access to the user's computer.
You cannot see their screen, desktop, open windows, or file contents. You can ONLY access the structured
data this API exposes — running processes, binary metadata, resource metrics, security event history,
and publisher information. Never imply you are "looking at" or "viewing" the user's PC.
Always frame responses as "the data shows..." or "according to AppControl..." rather than
"I can see..." or "looking at your machine..."

## Timestamps

All timestamps in the API are **milliseconds since Unix epoch (UTC)** — e.g. ` +
	`1710806400000 = 2024-03-19 00:00:00 UTC. This applies to all timestamp fields ` +
	`in responses (start_time, timestamp, last_access_times values) and all timestamp ` +
	`parameters you pass to tools (start_time, end_time, first_seen_after). ` +
	`Call get_stats first — it returns current_time so you can compute relative ranges ` +
	`like "last 24 hours" = current_time - 86400000, "last hour" = current_time - 3600000.`

func clampLimit(limit int) int {
	if limit < 1 {
		return 100 // default
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

func textResult(body string) (*mcp.CallToolResult, any, error) {
	var structured any
	_ = json.Unmarshal([]byte(body), &structured)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: body}},
	}, structured, nil
}

func errResult(err error) (*mcp.CallToolResult, any, error) {
	return nil, nil, err
}

// ---------------------------------------------------------------------------
// Tool: list_binaries
// ---------------------------------------------------------------------------

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

Returns binaries with metadata: name, filename, filename_hash, path, SHA256 hash, publisher, version, size, running process count, last_access_times, and activities.

filename_hash groups binaries by file path. Multiple binary records can share the same filename_hash when the file at that path changed over time (e.g., updates). When a new version appears, a new record is created and older records gain a NoLongerSeen timestamp in last_access_times.

last_access_times is an object mapping access types (Webcam, Mic, Location, FirstTimeSeen, NoLongerSeen, LastTimeHashChanged) to epoch-ms timestamps. activities is an array of current hardware access: Webcam, Mic, Location.

Tip: Unsigned binaries in user-writable paths are highest risk. Binaries with no publisher and a path under Downloads, Temp, or AppData warrant scrutiny.`

func listBinaries(_ context.Context, _ *mcp.CallToolRequest, input ListBinariesInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
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

	body, err := c.Get("/api/v1/binaries", params)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: get_binary
// ---------------------------------------------------------------------------

type GetBinaryInput struct {
	BinaryID  int    `json:"binary_id,omitempty" jsonschema:"A single binary ID to look up."`
	BinaryIDs string `json:"binary_ids,omitempty" jsonschema:"Comma-separated list of binary IDs for batch lookup. E.g. 42,55,103. Returns an array of binary objects. Use this when you have multiple IDs from history events or process listings."`
}

const getBinaryDesc = `Get detailed info for one or more binaries by ID (batch with comma-separated IDs) — path, hash, signature, publisher, first-seen time, and running status.

Returns full metadata including hashes, publisher info, file timestamps, execution history, and trust status. Use this to drill into specific binaries of interest.

Supports batch mode: pass multiple IDs at once to avoid repeated calls. For example, after query_history returns 20 NewBinarySeen events, pass all their binary_ids here in one call instead of 20 separate calls.`

func getBinary(_ context.Context, _ *mcp.CallToolRequest, input GetBinaryInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}

	if input.BinaryIDs != "" {
		params := url.Values{}
		params.Set("ids", input.BinaryIDs)
		body, err := c.Get("/api/v1/binaries", params)
		if err != nil {
			return errResult(err)
		}
		return textResult(body)
	}

	if input.BinaryID != 0 {
		body, err := c.Get(fmt.Sprintf("/api/v1/binaries/%d", input.BinaryID), nil)
		if err != nil {
			return errResult(err)
		}
		return textResult(body)
	}

	return errResult(fmt.Errorf("provide either binary_id or binary_ids"))
}

// ---------------------------------------------------------------------------
// Tool: list_processes
// ---------------------------------------------------------------------------

type ListProcessesInput struct {
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of results (1-200, default 100). Use offset to paginate."`
	Offset       int    `json:"offset,omitempty" jsonschema:"Number of results to skip (default 0)."`
	Fields       string `json:"fields,omitempty" jsonschema:"Comma-separated list of fields to include. When omitted, all fields EXCEPT 'services' are returned. Available: name, username, start_time, elevation, flags, parent_binary_id, parent_process_id, os_parent_process_id, services. 'services' (the Windows services hosted by the process) is opt-in — include it explicitly to attach it; it is never in the default response. 'os_parent_process_id' is the raw OS parent PID (uncollapsed)."`
	Search       string `json:"search,omitempty" jsonschema:"Case-insensitive substring search across name, username, and command line. Useful for finding processes by path fragment (e.g. 'Temp', 'Downloads') or executable name."`
	Username     string `json:"username,omitempty" jsonschema:"Case-insensitive substring match on username. e.g. 'SYSTEM' matches 'NT AUTHORITY\\SYSTEM', 'Alex' matches 'DESKTOP-X\\Alex'."`
	BinaryID     int    `json:"binary_id,omitempty" jsonschema:"Return only processes for this binary ID. Useful to find all running instances of a specific application."`
	ElevatedOnly bool   `json:"elevated_only,omitempty" jsonschema:"If true, return only elevated (admin) processes."`
	Flags        string `json:"flags,omitempty" jsonschema:"Comma-separated flag names that MUST all be present. E.g. 'Elevated,Service' returns only elevated services."`
	ExcludeFlags string `json:"exclude_flags,omitempty" jsonschema:"Comma-separated flag names that must NOT be present. E.g. 'System,Service' excludes system and service processes, showing only user-session processes."`
}

const listProcessesDesc = `List currently running processes with binary ID, name, path, PID, and start time. Filterable by fields.

Returns running processes with their binary ID, name, username, start time, elevation type, and flags. process_id and binary_id are always returned. Use binary_id to cross-reference with list_binaries/get_binary.

Flags is an array of strings: Elevated, Service, System, Debugged, Suspended, Protected, Subsystem, Immersive.

To find service-host processes and see which services they host, filter flags="Service" and set fields to include "services" (e.g. fields="name,services"). Each services entry has name, display_name, description, path, and start_type. The "services" field is opt-in — it is only attached when you list it in fields. The whole system service catalog (including stopped services) is available via the list_services tool.`

func listProcesses(_ context.Context, _ *mcp.CallToolRequest, input ListProcessesInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))
	setStr(params, "fields", input.Fields)
	setStr(params, "search", input.Search)
	setStr(params, "username", input.Username)
	setInt(params, "binary_id", input.BinaryID)
	setBool(params, "elevated_only", input.ElevatedOnly)
	setStr(params, "flags", input.Flags)
	setStr(params, "exclude_flags", input.ExcludeFlags)

	body, err := c.Get("/api/v1/processes", params)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: list_publishers
// ---------------------------------------------------------------------------

type ListPublishersInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"Maximum number of results (1-200, default 100). Use offset to paginate."`
	Offset int `json:"offset,omitempty" jsonschema:"Number of results to skip (default 0)."`
}

const listPublishersDesc = `List code-signing publishers (certificate identities) — name, country, and linked binary/rule counts.

Publishers sign binaries with their certificate. A quarantine rule on a publisher blocks ALL binaries signed by that publisher. Returns publisher ID, name, country, and location.`

func listPublishers(_ context.Context, _ *mcp.CallToolRequest, input ListPublishersInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))

	body, err := c.Get("/api/v1/publishers", params)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: list_rules
// ---------------------------------------------------------------------------

type ListRulesInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"Maximum number of results (1-200, default 100). Use offset to paginate."`
	Offset int `json:"offset,omitempty" jsonschema:"Number of results to skip (default 0)."`
}

const listRulesDesc = `List quarantine rules — blocked binaries and publishers with rule type and creation time.

Returns only active deny rules. Each rule has a scope:
- "binary": blocks a specific application (identified by binary_id).
- "publisher": blocks all applications from a publisher (publisher_id).
- "all_unsigned": a special rule that blocks ALL unsigned (no code-signing certificate) applications from running. This is the most powerful rule.

If no rules are returned, nothing is currently quarantined.`

func listRules(_ context.Context, _ *mcp.CallToolRequest, input ListRulesInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))

	body, err := c.Get("/api/v1/rules", params)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: query_history
// ---------------------------------------------------------------------------

type QueryHistoryInput struct {
	StartTime    int64  `json:"start_time,omitempty" jsonschema:"Filter events after this time (ms since Unix epoch UTC). For 'last 24h' use get_stats().current_time - 86400000."`
	EndTime      int64  `json:"end_time,omitempty" jsonschema:"Filter events before this time (ms since Unix epoch UTC)."`
	EventType    string `json:"event_type,omitempty" jsonschema:"Filter by one or more event type names (comma-separated). E.g. 'NewBinarySeen,BinaryHashChanged,ThreatDetected,DriverServiceAdded' for a security sweep in a single call."`
	BinaryIDs    []int  `json:"binary_ids,omitempty" jsonschema:"Filter to events for specific binaries only. Useful to get the full history of a suspicious binary after initial triage."`
	PublisherIDs []int  `json:"publisher_ids,omitempty" jsonschema:"Filter to events for binaries signed by these publishers. Get publisher IDs from list_publishers."`
	UnsignedOnly bool   `json:"unsigned_only,omitempty" jsonschema:"If true, return only events for unsigned binaries. Combine with event_type for targeted queries like 'new unsigned binaries' (event_type='NewBinarySeen', unsigned_only=true)."`
	BeforeID     int    `json:"before_id,omitempty" jsonschema:"Pagination cursor. Pass the next_before_id value from a previous response to fetch the next page of older events."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of events (1-200, default 100). Use time ranges to narrow results."`
}

const queryHistoryDesc = `Query security event history — binary first-seen events, quarantine blocks, alerts, and process starts. Filterable by event type, time range, and binary ID.

Results are ordered newest-first. Use cursor-based pagination to page through large result sets: the response includes next_before_id — pass it as before_id in the next call to get the next page. All filters are preserved across pages.

Each event includes an inline "binary" summary (name, filename, hash_sha256, publisher_name) so you can triage without extra get_binary calls. Use get_binary only to drill into specific items.

Key event types to investigate:
- BlockProcess: binary denied execution (threat stopped or needs rule update)
- NewBinarySeen: previously unknown executable appeared
- BinaryHashChanged: known binary's hash changed (update or tampering)
- ThreatDetected: behavioral analysis flagged suspicious activity
- DriverServiceAdded: new kernel driver (always investigate)

All event types: TerminateProcess, CreateProcess, NewBinarySeen, BinaryHashChanged, StopService, StartService, BlockProcess, DriverServiceAdded, DriverServiceRemoved, WebcamAccessed, MicAccessed, LocationAccessed, AppRuleChanged, PublisherRuleChanged, ThreatDetected, ComputerIdle, ComputerActive.

Some events include a "detail" object with supplementary data:
- TerminateProcess: session_length (process lifetime in ms)
- DriverServiceAdded/Removed: name, description, image_path, publisher, is_driver, is_svchost_hosted
- ThreatDetected: threat (classification name), is_pup (potentially unwanted program, less severe than malware)
- AppRuleChanged/PublisherRuleChanged: publisher_id, target, action`

func queryHistory(_ context.Context, _ *mcp.CallToolRequest, input QueryHistoryInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
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

	body, err := c.Get("/api/v1/history", params)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: get_stats
// ---------------------------------------------------------------------------

const getStatsDesc = `Get service stats, current timestamp, and uptime/idle intervals showing when the PC was on, off, or idle. Call first to orient before using other tools.

Returns counts of known binaries, running processes, publishers, security rules, and alert status. Also returns current_time (ms since Unix epoch UTC) — use this as the reference for computing time ranges in other tools (e.g. last 24h = current_time - 86400000).

The response includes two interval maps covering the history retention window (up to 3 days):
- uptime_intervals: periods when the AppControl service was running. The service starts automatically with Windows, so these intervals generally match when the PC was turned on (unless AppControl was installed recently). Each entry has start/stop timestamps (ms). A start of 0 means the service was running since before recorded history; a stop of 0 means it is still running now. Gaps between these intervals are when the service (and typically the PC) was off and no monitoring data was collected.
- idle_intervals: periods when the computer was idle (no user input, workstation locked, or system sleeping). Same timestamp semantics — a start of 0 means idle since before recorded history; a stop of 0 means still idle now.

Use these intervals to understand gaps in monitoring data (gaps between uptime_intervals = service was off) and to discount resource metrics during idle periods when assessing user-facing performance. Report notable idle/off periods when summarizing system activity — e.g. "Computer was idle from HH:MM to HH:MM (duration)".

Call this first to orient yourself before drilling into specifics.`

func getStats(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}
	body, err := c.Get("/api/v1/stats", nil)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: get_monitoring
// ---------------------------------------------------------------------------

type GetMonitoringInput struct {
	StartTime  int64  `json:"start_time,omitempty" jsonschema:"Start of time range (ms since Unix epoch UTC). Use get_stats().current_time as reference. Defaults to 10 minutes ago."`
	EndTime    int64  `json:"end_time,omitempty" jsonschema:"End of time range (ms since Unix epoch UTC). Defaults to now."`
	Resolution int    `json:"resolution,omitempty" jsonschema:"Aggregation window in seconds. 1 = raw data (one point per second), higher values average metrics over that many seconds. Use higher resolution for longer time ranges to reduce data volume."`
	Type       string `json:"type,omitempty" jsonschema:"'system' for system-wide metrics, 'binary' for per-binary metrics. Defaults to 'system' if omitted."`
	BinaryIDs  []int  `json:"binary_ids,omitempty" jsonschema:"List of binary IDs to filter (only used when type='binary'). Omit to get data for all active binaries."`
	TopN       int    `json:"top_n,omitempty" jsonschema:"Only return the top N binaries ranked by peak value of the sort_by metric (only used when type='binary'). E.g. top_n=10 with sort_by='cpu' gives the 10 heaviest CPU consumers."`
	SortBy     string `json:"sort_by,omitempty" jsonschema:"Which resource metric to rank binaries by when using top_n or min_value. One of: 'cpu' (default), 'memory', 'disk', 'gpu', 'network'. 'network' ranks by combined rx+tx bytes. Only used when type='binary'."`
	MinValue   int    `json:"min_value,omitempty" jsonschema:"Minimum peak threshold for the sort_by metric (only used when type='binary'). Units depend on sort_by: cpu/gpu=percent (e.g. 5 means 5%%), memory/disk/network=bytes (e.g. 104857600 means 100 MB). Can be combined with top_n."`
}

const getMonitoringDesc = `Get time-series resource metrics — system-wide (CPU, memory, disk, GPU, network, temps) or per-binary with top-N/min-value filtering to find heavy resource consumers.

Timestamps are Unix epoch milliseconds (UTC). AppControl samples system and per-binary metrics once per second internally.

Two modes controlled by the 'type' parameter:
- type="system" (default): Returns system-wide metrics per time point — cpu_percent, memory_percent, disk_percent, net_rx_bytes, net_tx_bytes, process count, temperatures, and GPU load. Use this to spot overall performance anomalies.
- type="binary": Returns per-binary resource usage per time point — cpu_percent, memory_bytes, disk_bytes, net_rx_bytes, net_tx_bytes, process count, and GPU load for each binary active during that interval. Each entry includes the binary's name and path. Use sort_by + top_n + min_value to focus on heavy hitters by any resource type without needing to know binary IDs upfront.

NETWORK DATA — read this before drawing conclusions from net_* values:

1. System and per-binary network figures measure DIFFERENT things and are NOT expected to reconcile. The system figure is NIC-level octets, which includes protocol framing and traffic that has no owning process (ARP, ICMP, DHCP, VPN encapsulation, kernel-originated traffic). The per-binary figure is TCP/UDP payload attributed to a process. The system total is therefore normally LARGER than the sum of per-binary values, by construction. The response carries a net_semantics field stating this. Do NOT report the difference as unexplained traffic, a hidden process, or evidence of exfiltration — that gap is expected on every healthy machine.

2. net_app_available tells you whether per-binary network data is TRUSTWORTHY for a given sample. It appears per time point and as a whole-window summary at the response root. When it is false, per-binary net_rx_bytes/net_tx_bytes are UNKNOWN, not zero — the collector was not running for that sample. Never read a zero under net_app_available=false as "this application used no network". The root flag is true only when every returned sample was valid, so a mixed window reports false; use the per-time-point flags to see which samples you can rely on. System net_* values do not depend on this flag and remain valid regardless.

3. Traffic to the machine's own loopback address is excluded from both figures.

4. Short-lived processes that transmit and exit between one-second samples may not be attributed to their binary; their traffic still appears in the system total. Absence of per-binary network activity is therefore weak evidence, not proof.

To understand idle and off periods, use get_stats() which returns off_intervals and idle_intervals. Cross-reference those intervals with monitoring data to discount resource metrics during inactive periods.

Returns time series data points. Useful for correlating performance anomalies with security events from query_history.`

func getMonitoring(_ context.Context, _ *mcp.CallToolRequest, input GetMonitoringInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}
	params := url.Values{}
	setInt64(params, "start_time", input.StartTime)
	setInt64(params, "end_time", input.EndTime)
	setInt(params, "resolution", input.Resolution)
	setStr(params, "type", input.Type)
	setIntSlice(params, "binary_ids", input.BinaryIDs)
	setInt(params, "top_n", input.TopN)
	setStr(params, "sort_by", input.SortBy)
	setInt(params, "min_value", input.MinValue)

	body, err := c.Get("/api/v1/monitoring", params)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: get_hardware
// ---------------------------------------------------------------------------

const getHardwareDesc = `Get CPU, GPU, network adapter, and temperature sensor info for the monitored system.

Returns CPU name, GPU names, and whether temperature readings are supported for each. Use this to understand what hardware is present and whether temperature data in get_monitoring results is meaningful.

Also returns network_adapters: each entry has name, type (IANA ifType — 6 = ethernet, 71 = 802.11, 24 = loopback, 53 = virtual/tunnel), receive_link_speed and transmit_link_speed in bits/sec, up, and counted_in_total. Only adapters with counted_in_total=true contribute to the system-wide net_rx_bytes/net_tx_bytes in get_monitoring. Loopback, VPN tunnels, virtual switch ports and similar are deliberately excluded because their traffic is already counted on the physical adapter underneath, so counting both would double it. Use link speed to judge whether an observed transfer rate is near the adapter's capacity.

net_app_available here reflects whether the per-application network collector is running RIGHT NOW. That is a live health signal — it says nothing about whether historical samples in get_monitoring are trustworthy. For that, use the net_app_available fields inside the get_monitoring response itself.`

func getHardware(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}
	body, err := c.Get("/api/v1/hardware", nil)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Tool: list_services
// ---------------------------------------------------------------------------

type ListServicesInput struct {
	Search      string `json:"search,omitempty" jsonschema:"Case-insensitive substring match on service name, display name, or description. E.g. 'update', 'defender', 'sql'."`
	RunningOnly bool   `json:"running_only,omitempty" jsonschema:"If true, return only services the Service Control Manager reports as Running (state=Running). This correctly includes running kernel drivers, which have no user-mode host process (and therefore no pids)."`
	DriversOnly bool   `json:"drivers_only,omitempty" jsonschema:"If true, return only kernel driver services (is_driver=true). Drivers run in kernel mode with the highest privilege."`
	StartType   string `json:"start_type,omitempty" jsonschema:"Filter by start type. One of: Auto, Demand, Disabled, Boot, System (case-insensitive). Auto/Boot/System start without a logged-in user and are persistence-relevant."`
	Limit       int    `json:"limit,omitempty" jsonschema:"Maximum number of results (1-200, default 100). Use offset to paginate."`
	Offset      int    `json:"offset,omitempty" jsonschema:"Number of results to skip for pagination (default 0)."`
}

const listServicesDesc = `List Windows services from the system-wide catalog — running AND stopped. Filterable by name/description, running state, driver-only, and start type.

Each service includes: name, display_name, is_driver, svchost_hosted, start_type (Auto/Demand/Disabled/Boot/System/Unknown), state (Stopped/StartPending/StopPending/Running/ContinuePending/PausePending/Paused/Unknown), and running. description and path may be omitted when unknown. When a service has a live host process, it also includes pids and (when resolvable) the hosting binary_ids plus an inline binary summary.

running reflects the actual Service Control Manager state (running == state is Running), so it is accurate for kernel drivers too: a running driver reports running=true with an empty pids list (drivers have no host process). pids/binary_ids are only present for user-mode services that have a live host process.

Security relevance:
- start_type Auto/Boot/System = the service runs without a logged-in user, a common persistence mechanism. Newly-appeared auto-start services warrant scrutiny.
- is_driver services are kernel-mode (highest privilege) and correspond to DriverServiceAdded events in query_history.
- Service binaries in user-writable or unusual paths, and unsigned service binaries, are high-risk. Cross-reference a running service's binary_id with get_binary for signature/path/first-seen.
- svchost_hosted services are DLLs loaded into a shared svchost.exe host process.

To see which services a specific running process hosts, use list_processes with flags="Service" and fields including "services".`

func listServices(_ context.Context, _ *mcp.CallToolRequest, input ListServicesInput) (*mcp.CallToolResult, any, error) {
	c, err := getClient()
	if err != nil {
		return errResult(err)
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))
	setStr(params, "search", input.Search)
	setBool(params, "running_only", input.RunningOnly)
	setBool(params, "drivers_only", input.DriversOnly)
	setStr(params, "start_type", input.StartType)

	body, err := c.Get("/api/v1/services", params)
	if err != nil {
		return errResult(err)
	}
	return textResult(body)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "AppControl",
		Version: "1.0.0",
	}, &mcp.ServerOptions{
		Instructions: serverInstructions,
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_binaries",
		Description: listBinariesDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, listBinaries)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_binary",
		Description: getBinaryDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, getBinary)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_processes",
		Description: listProcessesDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, listProcesses)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_publishers",
		Description: listPublishersDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, listPublishers)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_rules",
		Description: listRulesDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, listRules)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "query_history",
		Description: queryHistoryDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, queryHistory)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_stats",
		Description: getStatsDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, getStats)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_monitoring",
		Description: getMonitoringDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, getMonitoring)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_hardware",
		Description: getHardwareDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, getHardware)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_services",
		Description: listServicesDesc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, listServices)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
