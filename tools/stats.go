package tools

import (
	"context"
	"encoding/json"
)

const getStatsDesc = `Get service stats, current timestamp, and uptime/paused/idle intervals showing when the PC was on, off, paused, or idle. Call first to orient before using other tools.

Returns binary_count, process_count, publisher_count, app_rules_count, publisher_rules_count, unread_alerts, and total_alerts. Also returns current_time (ms since Unix epoch UTC) — use this as the reference for computing time ranges in other tools (e.g. last 24h = current_time - 86400000).

The response includes three interval arrays covering the history retention window (3 days on the free tier, longer with a paid licence):
- uptime_intervals: periods when the AppControl service was running. The service starts automatically with Windows, so these intervals generally match when the PC was turned on (unless AppControl was installed recently). Each entry has start/stop timestamps (ms). A start of 0 means the service was running since before recorded history; a stop of 0 means it is still running now. Gaps between these intervals are when the service (and typically the PC) was off and no monitoring data was collected.
- paused_intervals: periods when the user paused AppControl. While paused the service and its driver are stopped: nothing is monitored, no events are recorded, and there are no metrics for the period at all. Data for a paused interval is ABSENT, not zero — never read the gap as idle, as "no activity", or as the PC being off; use this array to tell a pause from a shutdown. Same timestamp semantics (a stop of 0 would mean still paused, which you cannot observe since the API is down while paused).
- idle_intervals: periods when the computer was idle (no user input, workstation locked, or system sleeping). Same timestamp semantics — a start of 0 means idle since before recorded history; a stop of 0 means still idle now.

Use these intervals to understand gaps in monitoring data (gaps between uptime_intervals = service was off; paused_intervals = the user switched monitoring off) and to discount resource metrics during idle periods when assessing user-facing performance. Report notable idle/paused/off periods when summarizing system activity — e.g. "Computer was idle from HH:MM to HH:MM (duration)".

Call this first to orient yourself before drilling into specifics.`

func getStats(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input struct{}
	if err := decode(args, &input); err != nil {
		return "", err
	}
	return b.Get(ctx, "/api/v1/stats", nil)
}
