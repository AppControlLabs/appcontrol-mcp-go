package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

const maxLimit = 200

// The API's own cap on monitoring time points, which is also its default.
const maxMonitoringPoints = 1000

// Spec is one read-only tool: its MCP name and description, the schema of its
// arguments, and the call that turns raw arguments into one Backend.Get.
type Spec struct {
	Name        string
	Description string
	Input       *jsonschema.Schema
	Call        func(ctx context.Context, b Backend, args json.RawMessage) (string, error)
}

// Specs returns the ten read-only tools. Each issues exactly one GET.
func Specs() []Spec {
	return []Spec{
		{Name: "list_binaries", Description: listBinariesDesc, Input: listBinariesSchema, Call: listBinaries},
		{Name: "get_binary", Description: getBinaryDesc, Input: getBinarySchema, Call: getBinary},
		{Name: "list_processes", Description: listProcessesDesc, Input: listProcessesSchema, Call: listProcesses},
		{Name: "list_publishers", Description: listPublishersDesc, Input: listPublishersSchema, Call: listPublishers},
		{Name: "list_rules", Description: listRulesDesc, Input: listRulesSchema, Call: listRules},
		{Name: "query_history", Description: queryHistoryDesc, Input: queryHistorySchema, Call: queryHistory},
		{Name: "get_stats", Description: getStatsDesc, Input: getStatsSchema, Call: getStats},
		{Name: "get_monitoring", Description: getMonitoringDesc, Input: getMonitoringSchema, Call: getMonitoring},
		{Name: "get_hardware", Description: getHardwareDesc, Input: getHardwareSchema, Call: getHardware},
		{Name: "list_services", Description: listServicesDesc, Input: listServicesSchema, Call: listServices},
	}
}

var (
	listBinariesSchema   = schemaFor[ListBinariesInput]()
	getBinarySchema      = schemaFor[GetBinaryInput]()
	listProcessesSchema  = schemaFor[ListProcessesInput]()
	listPublishersSchema = schemaFor[ListPublishersInput]()
	listRulesSchema      = schemaFor[ListRulesInput]()
	queryHistorySchema   = schemaFor[QueryHistoryInput]()
	getStatsSchema       = schemaFor[struct{}]()
	getMonitoringSchema  = monitoringSchema()
	getHardwareSchema    = schemaFor[struct{}]()
	listServicesSchema   = schemaFor[ListServicesInput]()
)

func schemaFor[T any]() *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	return s
}

// decode fills v from the tool arguments; empty and null arguments leave it zero.
func decode(args json.RawMessage, v any) error {
	args = bytes.TrimSpace(args)
	if len(args) == 0 || bytes.Equal(args, []byte("null")) {
		return nil
	}
	return json.Unmarshal(args, v)
}

func clampLimit(limit int) int {
	if limit < 1 {
		return 100 // default
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

func setStr(params url.Values, key, val string) {
	if val != "" {
		params.Set(key, val)
	}
}

func setInt(params url.Values, key string, val int) {
	if val != 0 {
		params.Set(key, strconv.Itoa(val))
	}
}

func setInt64(params url.Values, key string, val int64) {
	if val != 0 {
		params.Set(key, strconv.FormatInt(val, 10))
	}
}

func setBool(params url.Values, key string, val bool) {
	if val {
		params.Set(key, "1")
	}
}

func setIntSlice(params url.Values, key string, vals []int) {
	if len(vals) == 0 {
		return
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(v)
	}
	params.Set(key, strings.Join(parts, ","))
}

// Instructions is the server-level guidance handed to every MCP client.
const Instructions = `# AppControl Application Monitor -- Domain Knowledge

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
	`Binaries may also track resource access (Webcam, Mic, Location, Network) and connections ` +
	`to this MCP API (McpConnection) in last_access_times, and currently-ongoing hardware or ` +
	`MCP access in the activities field.

**A binary record is one version, not one application.** A replacement record starts ` +
	`with only its own FirstTimeSeen or LastTimeHashChanged marker -- it does NOT inherit ` +
	`the resource-access timestamps (Webcam, Mic, Location, Network) recorded by the ` +
	`versions it replaced. Those stay on the older, retired records. So a single record's ` +
	`last_access_times describes only that one build. To answer anything about "this ` +
	`application" -- has it ever used the mic, when did it last touch the network -- group ` +
	`records by filename_hash AND filename, then merge across the group as described in ` +
	`list_binaries. Reading one record in isolation systematically under-reports any app ` +
	`that has ever been updated, and an app that updates often can look like it has never ` +
	`used a resource at all.

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
- ` + "`AppRuleChanged`" + ` / ` + "`PublisherRuleChanged`" + ` -- a rule changed: launch deny (quarantine), network block or ignore; one event per changed action, action NotSet means cleared
- ` + "`CreateProcess`" + ` / ` + "`TerminateProcess`" + ` -- process lifecycle
- ` + "`StartService`" + ` / ` + "`StopService`" + ` -- AppControl service lifecycle
- ` + "`ComputerIdle`" + ` / ` + "`ComputerActive`" + ` -- computer idle state transitions (user inactivity, workstation lock, or sleep)
- ` + "`FirstNetworkAccess`" + ` -- a binary used the network for the first time
- ` + "`McpAccessed`" + ` -- an AI agent connected to this MCP API (your own client produces these)
- ` + "`CriticalTemperature`" + ` / ` + "`TemperatureRecovered`" + ` -- a CPU or GPU sensor crossed its limit and came back under it
- ` + "`StartupItem`" + ` -- a run-on-startup entry appeared or its command changed (persistence)
- ` + "`HostsFile`" + ` -- the hosts file's entries or its location changed
- ` + "`BrowserExtension`" + ` -- a browser extension was added or its permissions grew
- ` + "`TimelinePin`" + ` -- a marker the user placed on the timeline; not security-relevant

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
	`process, or exfiltration. Each time point carries its own net_app_available flag; ` +
	`where it is false, that sample's per-binary network values are UNKNOWN rather than ` +
	`zero — treat them as missing data, not as evidence that an application used no ` +
	`network.

**Absent means no reading.** Every metric that can be unavailable — CPU, GPU and disk ` +
	`temperatures, battery figures, the per-binary power estimate, per-binary network — is ` +
	`omitted from a response when there was no reading, never written as 0. A missing key is ` +
	`"not measured", not "zero". The same holds for whole time ranges: while AppControl is ` +
	`paused (get_stats paused_intervals) or off, there are no data points at all.

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
