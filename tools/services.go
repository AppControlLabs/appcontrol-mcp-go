package tools

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

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

func listServices(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input ListServicesInput
	if err := decode(args, &input); err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("offset", strconv.Itoa(input.Offset))
	params.Set("limit", strconv.Itoa(clampLimit(input.Limit)))
	setStr(params, "search", input.Search)
	setBool(params, "running_only", input.RunningOnly)
	setBool(params, "drivers_only", input.DriversOnly)
	setStr(params, "start_type", input.StartType)
	return b.Get(ctx, "/api/v1/services", params)
}
