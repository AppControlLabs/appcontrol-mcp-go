package tools

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

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

const listProcessesDesc = `List currently running processes with binary ID, name, username, PID, and start time. Filterable by fields.

Returns running processes. process_id (the PID) and binary_id are always returned; the default fields are name, username, start_time, elevation (None, Limited, or Full — Full is an administrator token), flags, parent_process_id, and parent_binary_id (absent when the parent is unknown). The executable path is not part of a process entry — use binary_id with get_binary or list_binaries for path, hash, and publisher.

Flags is an array of strings: Elevated, Service, System, Debugged, Suspended, Protected, Subsystem, Immersive.

To find service-host processes and see which services they host, filter flags="Service" and set fields to include "services" (e.g. fields="name,services"). Each services entry has name, display_name, description, path, and start_type. The "services" field is opt-in — it is only attached when you list it in fields. The whole system service catalog (including stopped services) is available via the list_services tool.`

func listProcesses(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input ListProcessesInput
	if err := decode(args, &input); err != nil {
		return "", err
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
	return b.Get(ctx, "/api/v1/processes", params)
}
