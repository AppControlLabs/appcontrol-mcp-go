# Download appcontrol-mcp.exe if needed, then launch it.
# Used as the MCP server command so the binary is ready before stdio begins.

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$binaryName = "appcontrol-mcp.exe"
$binaryPath = Join-Path $env:CLAUDE_PLUGIN_DATA $binaryName
$versionFile = Join-Path $env:CLAUDE_PLUGIN_DATA "version"
$releaseUrl = "https://github.com/AppControlLabs/appcontrol-mcp-go/releases/latest/download/$binaryName"

# Read plugin version
$pluginJson = Get-Content (Join-Path $env:CLAUDE_PLUGIN_ROOT ".claude-plugin\plugin.json") -Raw | ConvertFrom-Json
$pluginVersion = $pluginJson.version

# Download if binary missing or version changed
$needsDownload = $true
if ((Test-Path $binaryPath) -and (Test-Path $versionFile)) {
    $installedVersion = (Get-Content $versionFile -Raw).Trim()
    if ($installedVersion -eq $pluginVersion) {
        $needsDownload = $false
    }
}

if ($needsDownload) {
    if (-not (Test-Path $env:CLAUDE_PLUGIN_DATA)) {
        New-Item -ItemType Directory -Path $env:CLAUDE_PLUGIN_DATA -Force | Out-Null
    }
    # Write status to stderr so it doesn't interfere with MCP stdio
    [Console]::Error.WriteLine("Downloading AppControl MCP server v$pluginVersion...")
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $releaseUrl -OutFile $binaryPath -UseBasicParsing
    Set-Content -Path $versionFile -Value $pluginVersion -NoNewline
    [Console]::Error.WriteLine("AppControl MCP server v$pluginVersion installed.")
}

# Launch the MCP server — stdin/stdout pass through for MCP stdio transport
& $binaryPath
