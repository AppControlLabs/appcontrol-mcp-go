package tools

import (
	"context"
	"encoding/json"
)

const getHardwareDesc = `Get CPU, GPU, disk, battery, network adapter, and temperature sensor info for the monitored system.

Returns cpu (name, or null when unknown), gpus, disks, batteries, power_model, and network_adapters, with temperature_supported on each sensor-bearing device. Use this to understand what hardware is present and whether temperature, battery, and power data in get_monitoring is meaningful: a device with temperature_supported=false never has a reading, and a reading missing from get_monitoring for a supported device means it was not read at that moment, not that it was 0.

Each gpus entry has gpu_index (the small integer get_monitoring and temperature events call gpu_id / gpu_index — use it to join), gpu_id (the adapter's hardware identifier string), name, is_available (currently present), and temperature_supported. Each disks entry has disk_id (joins get_monitoring's disk temperatures), name, present (currently attached — an id is permanent, so a removed drive keeps its row), temperature_supported, and warning_c / critical_c (the drive's own thresholds; null when it reports none).

Thermal limits: the CPU and each GPU with temperature support carry temperature_limit_c (the hardware limit), temperature_limit_from_vendor (true when the vendor reported it rather than a default being assumed), and critical_threshold_c — the user's alert threshold, null when the alert judges against the hardware limit itself. CriticalTemperature events in query_history fire against the threshold when set, otherwise the limit.

batteries lists each battery (name, manufacturer, relative_only); empty on a desktop. relative_only=true means the battery reports percent only and never a rate, so get_monitoring will have charge_percent but no discharge_mw / charge_mw and no per-binary power estimate. power_model is present only with a battery: calibrated (false = the per-app power estimate still uses generic defaults because the machine has not spent enough time discharging to fit; treat estimates as rough), fitted_at (epoch ms of the accepted fit), and on_battery_hours (the hours of discharge the fit is based on).

Also returns network_adapters: each entry has name, type (IANA ifType — 6 = ethernet, 71 = 802.11, 24 = loopback, 53 = virtual/tunnel), receive_link_speed and transmit_link_speed in bits/sec, up, and counted_in_total. Only adapters with counted_in_total=true contribute to the system-wide net_rx_bytes/net_tx_bytes in get_monitoring. Loopback, VPN tunnels, virtual switch ports and similar are deliberately excluded because their traffic is already counted on the physical adapter underneath, so counting both would double it. Use link speed to judge whether an observed transfer rate is near the adapter's capacity.

net_app_available here reflects whether the per-application network collector is running RIGHT NOW. That is a live health signal — it says nothing about whether historical samples in get_monitoring are trustworthy. For that, use the per-time-point net_app_available flag inside the get_monitoring response, which is recorded per sample. These are two different questions and the same field name answers only the one asked of this endpoint.`

func getHardware(ctx context.Context, b Backend, args json.RawMessage) (string, error) {
	var input struct{}
	if err := decode(args, &input); err != nil {
		return "", err
	}
	return b.Get(ctx, "/api/v1/hardware", nil)
}
