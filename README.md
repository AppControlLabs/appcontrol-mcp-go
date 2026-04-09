<p align="center">
  <a href="https://www.appcontrol.com"><img src="img/logo.png" width="512" alt="AppControl logo" /></a>
</p>

<h2 align="center">AppControl MCP Server</h2>

<p align="center">
  An <a href="https://modelcontextprotocol.io/">MCP</a> server that gives AI agents and IDEs like Claude, Cursor, and Windsurf <strong>read-only</strong> access to historical resource usage and system security data gathered by the <a href="https://www.appcontrol.com">AppControl</a> Windows app, including binaries, publishers, quarantine rules, events, and monitoring, all through natural language.
</p>
<P>
<p align="center">
  <a href="https://github.com/AppControlLabs/appcontrol-mcp-go/releases/latest">
    <img alt="Download Latest Release" src="https://img.shields.io/badge/Download-Latest%20Release-blue?style=for-the-badge">
  </a>
</p>

## Prerequisites

- [AppControl](https://www.appcontrol.com) running with MCP API enabled
- Windows only

## Installation

There are two ways to install the server: as an **MCPB package** (recommended for Claude Desktop) or as a **standalone executable**.

### Option A — MCPB Package (Claude Desktop)

1. Download `appcontrol.mcpb` from the [latest release](https://github.com/AppControlLabs/appcontrol-mcp-go/releases/latest).
2. Open Claude Desktop app, go to Settings -> Extensions -> Advanced Settings and click "Install Extension". Choose your newly downloaded `.mcpb` file — Claude Desktop will install it automatically.
3. Restart Claude Desktop app by right-clicking the Claude tray icon and selecting "Quit" then start it again.

### Option B - Claude Code plugin marketplace (Claude Code)

Add the marketplace in Claude Code:
```bash
/plugin marketplace add appcontrollabs/appcontrol-mcp-go
```

Install the plugin:
```bash
/plugin install appcontrol-mcp@appcontrollabs
```

Reload plugins:
```bash
/reload-plugins
```

### Option C — Standalone Executable

1. Download `appcontrol-mcp.exe` from the [latest release](https://github.com/AppControlLabs/appcontrol-mcp-go/releases/latest).
2. Place it somewhere permanent, e.g. `C:\MCP\appcontrol-mcp.exe`.
3. Configure your AI client as shown below.

## Configuration

If you installed via the MCPB package in Claude Desktop, no further configuration is needed. For the standalone executable, add the server to your AI client's MCP configuration.

<details>
<summary><strong>Claude Code (CLI)</strong></summary>

```bash
claude mcp add appcontrol C:\MCP\appcontrol-mcp.exe
```

</details>

<details>
<summary><strong>OpenAI Codex (CLI)</strong></summary>

```bash
codex mcp add appcontrol C:\MCP\appcontrol-mcp.exe
```

</details>

<details>
<summary><strong>OpenAI Codex (Codex Desktop)</strong></summary>

Open your Codex desktop app and navigate to File -> Settings -> MCP servers. Click "Add server" and fill the following fields:

- **Name:** _AppControl_
- **Command to launch:** _C:\MCP\appcontrol-mcp.exe_

Leave the rest unchanged and click **Save**.

</details>

<details>
<summary><strong>Gemini (CLI)</strong></summary>

Add to your Gemini configuration `~\.gemini\settings.json`:

```json
{
  "mcpServers": {
    "appcontrol": {
      "command": "C:/MCP/appcontrol-mcp.exe",
      "args": [],
      "timeout": 15000
    }
  }

}
```

</details>

<details>
<summary><strong>VS Code (Copilot / Continue / Cline)</strong></summary>

Add to your workspace `.vscode/mcp.json`:

```json
{
  "servers": {
    "appcontrol": {
      "command": "C:/MCP/appcontrol-mcp.exe"
    }
  }
}
```

</details>

<details>
<summary><strong>Cursor</strong></summary>

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "appcontrol": {
      "command": "C:/MCP/appcontrol-mcp.exe"
    }
  }
}
```

</details>

<details>
<summary><strong>Windsurf</strong></summary>

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "appcontrol": {
      "command": "C:/MCP/appcontrol-mcp.exe"
    }
  }
}
```

</details>

## Example Prompts

Once connected, try asking your AI assistant:

- *"What unsigned applications have been running on this system?"*
- *"What binaries on my PC originate from outside the United States and what are the top countries?"*
- *"Show me all AppControl blocked process events from the last 24 hours"*
- *"Are there any binaries running from Temp or Downloads folders?"*
- *"What's currently quarantined? Are unsigned apps blocked?"*
- *"What new binaries appeared today? Are any of them suspicious?"*
- *"While I walked up to my locked PC my fan was roaring, what was causing that?"*
- *"Which publishers have the most binaries on this system?"*
- *"Show me processes running with elevated privileges that aren't from Microsoft"*
- *"Which binaries have had their hash change recently?"*
- *"Did any applications access my webcam while my PC was idle, and if so which ones?"*

## Available Tools

The MCP server exposes 9 read-only tools:

| Tool | Description |
|------|-------------|
| `get_stats` | Get service stats, current timestamp, and uptime/idle intervals showing when the PC was on, off, or idle. |
| `list_binaries` | List tracked binaries with filters — unsigned-only, currently-running, first-seen-after date, path substring, or publisher ID. |
| `get_binary` | Get detailed info for one or more binaries by ID (batch with comma-separated IDs) — path, hash, signature, publisher, first-seen time, and running status. |
| `list_processes` | List currently running processes with binary ID, name, path, PID, and start time. Filterable by fields. |
| `list_publishers` | List code-signing publishers (certificate identities) — name, country, and linked binary/rule counts. |
| `list_rules` | List quarantine rules — blocked binaries and publishers with rule type and creation time. |
| `query_history` | Query security event history — binary first-seen events, quarantine blocks, alerts, and process starts. Filterable by event type, time range, and binary ID. |
| `get_monitoring` | Get time-series resource metrics — system-wide (CPU, memory, disk, GPU, temps) or per-binary with top-N/min-value filtering to find heavy resource consumers. |
| `get_hardware` | Get CPU, GPU, and temperature sensor info for the monitored system. |

All tools are **read-only**. The MCP server cannot modify rules, block/allow binaries, or change any service configuration.


## Building from Source

```bash
go build -ldflags "-s -w" -o appcontrol-mcp.exe .
```

## License

MIT

This repository contains the open MCP server for AppControl. The AppControl desktop application remains proprietary.
