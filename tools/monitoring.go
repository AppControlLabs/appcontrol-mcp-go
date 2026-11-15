package tools

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/google/jsonschema-go/jsonschema"
)

// The service refuses a wider aggregation window: buckets align to the epoch, so
// one far wider than the range would be timestamped outside it.
const maxResolution = 30 * 24 * 3600

type GetMonitoringInput struct {
	StartTime  int64  `json:"start_time,omitempty" jsonschema:"Start of time range (ms since Unix epoch UTC). Use get_stats().current_time as reference. Defaults to 10 minutes ago."`
	EndTime    int64  `json:"end_time,omitempty" jsonschema:"End of time range (ms since Unix epoch UTC). Defaults to now."`
	Resolution int    `json:"resolution,omitempty" jsonschema:"Aggregation window in seconds, at most 2592000 (30 days). 1 = raw data (one point per second); higher values fold each window into one point — percentages are averaged, byte counters are summed. Pick it so (end_time - start_time) / resolution stays within limit, e.g. 24 hours at 300 = 288 points. The service raises it on its own when a range is too wide; the spacing of the returned timestamps shows what was used."`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum number of time points returned (1-1000, default 1000). Points are oldest-first and the newest are dropped past the limit, so widen resolution rather than rely on this cap."`
	Type       string `json:"type,omitempty" jsonschema:"'system' for system-wide metrics, 'binary' for per-binary metrics. Defaults to 'system' if omitted."`
	BinaryIDs  []int  `json:"binary_ids,omitempty" jsonschema:"List of binary IDs to filter (only used when type='binary'). Omit to get data for all active binaries."`
	TopN       int    `json:"top_n,omitempty" jsonschema:"Only return the top N binaries ranked by peak value of the sort_by metric (only used when type='binary'). E.g. top_n=10 with sort_by='cpu' gives the 10 heaviest CPU consumers."`
	SortBy     string `json:"sort_by,omitempty" jsonschema:"Which resource metric to rank binaries by when using top_n or min_value. One of: 'cpu' (default), 'memory', 'disk', 'gpu', 'network', 'power'. 'network' ranks by combined rx+tx bytes; 'power' ranks by the on-battery power_mw_estimate and finds nothing for a range spent on AC. Only used when type='binary'."`
	MinValue   int    `json:"min_value,omitempty" jsonschema:"Minimum peak threshold for the sort_by metric (only used when type='binary'). Units depend on sort_by: cpu/gpu=percent (e.g. 5 means 5%%), memory/disk/network=bytes (e.g. 104857600 means 100 MB), power=milliwatts. Can be combined with top_n."`
}

const getMonitoringDesc = `Get time-series resource metrics — system-wide (CPU, memory, disk, GPU, network, temperatures, battery) or per-binary (with an on-battery power estimate) with top-N/min-value filtering to find heavy resource consumers.

Timestamps are Unix epoch milliseconds (UTC). AppControl samples system and per-binary metrics once per second internally. Points come oldest first, at most limit (default 1000) of them, and the service coarsens the resolution on its own when the range is too wide for the one requested — check the spacing of the returned timestamps before computing rates.

Two modes controlled by the 'type' parameter:
- type="system" (default): Returns system-wide metrics per time point — cpu_percent, memory_percent, memory_bytes, memory_total_bytes, disk_percent, net_rx_bytes, net_tx_bytes, processes, temperature, battery, and gpu_load (array of {gpu_id, load_percent}). The response also carries power_periods (see BATTERY). Use this to spot overall performance anomalies.
- type="binary": Returns per-binary resource usage per time point — cpu_percent, memory_bytes, disk_bytes, net_rx_bytes, net_tx_bytes, processes, gpu_load, and the binary's name and path (both absent when the record no longer exists) for each binary active during that interval. Use sort_by + top_n + min_value to focus on heavy hitters by any resource type without needing to know binary IDs upfront.

Byte counters (disk_bytes, net_rx_bytes, net_tx_bytes) are totals over the point's window, not rates; at resolution 1 the two coincide. Divide by the window length for a rate.

TEMPERATURES — absent means no reading, never zero. temperature is an object with cpu (degrees C), gpu (array of {gpu_id, temperature}) and disk (array of {disk_id, temperature}); each key exists only when that sensor delivered a reading in the window. A missing cpu, a GPU or disk absent from its array, or no temperature object at all means the sensor was not read (unsupported, asleep, or removed) — do not report it as 0 °C, as cool, or as a sensor failure. gpu_id here is gpu_index in get_hardware; disk_id matches get_hardware's disks. Get names and limits from get_hardware.

BATTERY (system mode) — battery is present only on a machine with a battery and only for points where a sample carried a reading; absent means no reading, not 0 %. Fields: charge_percent (mean), samples (readings in the window), ac_samples (of those, on AC), discharge_samples with discharge_mw (mean draw while discharging; both only when discharging), charge_samples with charge_mw (mean while charging), unattributed_mw (the share of the discharge the per-app model assigns to no app: display, idle platform), and time_remaining_s (Windows' own estimate; live points only, absent when unknown or on AC). power_periods lists every unbroken stretch on one power source overlapping the range, oldest first: start, end, source (battery, charging, plugged_in — plugged_in is on AC and not charging: full, or held at a charge limit), start_charge_percent, end_charge_percent. A gap of more than 30 s without a reading ends a period. Use power_periods to say when the machine ran on battery; use get_hardware batteries / power_model to judge how far to trust the wattage figures.

PER-BINARY POWER (binary mode) — each time point carries battery_samples, the number of samples in the window that were discharging with a rate reading. When it is above 0 each binary carries power_mw_estimate: the per-machine model's estimate of that binary's mean draw, fitted to measured discharge from CPU, GPU and network activity. It is an attribution, not a measurement — present it as an estimate; the binaries' estimates plus the system point's unattributed_mw reconcile with discharge_mw. Energy over a point is power_mw_estimate x battery_samples / 3600 mWh. When battery_samples is 0 (on AC, or no battery) power_mw_estimate is absent — there is no power figure, not zero draw. sort_by="power" ranks by this estimate and min_value is then in mW.

NETWORK DATA — read this before drawing conclusions from net_* values:

1. System and per-binary network figures measure DIFFERENT things and are NOT expected to reconcile. The system figure is NIC-level octets, which includes protocol framing and traffic that has no owning process (ARP, ICMP, DHCP, VPN encapsulation, kernel-originated traffic). The per-binary figure is TCP/UDP payload attributed to a process. The system total is therefore normally LARGER than the sum of per-binary values, by construction. The response carries a net_semantics field stating this. Do NOT report the difference as unexplained traffic, a hidden process, or evidence of exfiltration — that gap is expected on every healthy machine.

2. Each time point carries net_app_available, telling you whether per-binary network data is TRUSTWORTHY for that specific sample. When it is false, that point's per-binary net_rx_bytes/net_tx_bytes are UNKNOWN, not zero — the collector was not running for that second. Never read a zero under net_app_available=false as "this application used no network". Availability is per sample and a window can be partly valid, so check the flag on the points you are actually reasoning about rather than assuming a whole range is uniform. A handful of false points is normal: the sample at each service start is unmeasured by definition. System net_* values do not depend on this flag and remain valid regardless.

3. Traffic to the machine's own loopback address is excluded from both figures.

4. Short-lived processes that transmit and exit between one-second samples may not be attributed to their binary; their traffic still appears in the system total. Absence of per-binary network activity is therefore weak evidence, not proof.

To understand idle, paused and off periods, use get_stats() which returns uptime_intervals, paused_intervals and idle_intervals. A range inside a paused interval or a gap between uptime intervals has no data points at all, not zero-valued ones. Cross-reference those intervals with monitoring data to discount resource metrics during inactive periods.

Returns time series data points. Useful for correlating performance anomalies with security events from query_history.`

// monitoringSchema adds the bounds and choices the service enforces, so a bad
// value is refused before any machine is asked.
func monitoringSchema() *jsonschema.Schema {
	s := schemaFor[GetMonitoringInput]()
	s.Properties["resolution"].Minimum = new(0.0)
	s.Properties["resolution"].Maximum = new(float64(maxResolution))
	s.Properties["type"].Enum = []any{"system", "binary"}
	s.Properties["sort_by"].Enum = []any{"cpu", "memory", "disk", "gpu", "network", "power"}
	return s
}

func getMonitoring(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input GetMonitoringInput
	if err := decode(args, &input); err != nil {
		return "", err
	}
	params := url.Values{}
	setInt64(params, "start_time", input.StartTime)
	setInt64(params, "end_time", input.EndTime)
	setInt(params, "resolution", input.Resolution)
	if input.Limit > 0 {
		setInt(params, "limit", min(input.Limit, maxMonitoringPoints))
	}
	setStr(params, "type", input.Type)
	setIntSlice(params, "binary_ids", input.BinaryIDs)
	setInt(params, "top_n", input.TopN)
	setStr(params, "sort_by", input.SortBy)
	setInt(params, "min_value", input.MinValue)
	return b.Get(ctx, "/api/v1/monitoring", params)
}
