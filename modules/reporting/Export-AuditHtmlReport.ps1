function Export-AuditHtmlReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[PSCustomObject]]$Findings,

        [Parameter(Mandatory)]
        [int]$TotalRiskScore,

        [Parameter(Mandatory)]
        [string]$RiskRating,

        [Parameter(Mandatory)]
        [bool]$ElevatedScan,

        [Parameter()]
        [string]$OutputPath = ".\security_audit_report.html"
    )

    # Calculate severity breakdown counts
    $critCount = @($Findings | Where-Object Severity -eq "Critical").Count
    $highCount = @($Findings | Where-Object Severity -eq "High").Count
    $medCount  = @($Findings | Where-Object Severity -eq "Medium").Count
    $lowCount  = @($Findings | Where-Object Severity -eq "Low").Count

    # Determine overall rating banner color
    $ratingColor = switch -Wildcard ($RiskRating) {
        "Optimal*"  { "#10b981" } # Emerald Green
        "Low*"      { "#3b82f6" } # Blue
        "Moderate*" { "#f59e0b" } # Amber
        default     { "#ef4444" } # Red
    }

    # Build HTML table rows dynamically
    $tableRows = ""
    if ($Findings.Count -gt 0) {
        foreach ($item in ($Findings | Sort-Object ScoreWeight -Descending)) {
            $sevClass = "badge-" + $item.Severity.ToLower()
            
            # HTML-encode dynamic text to prevent broken markup
            $safeTitle  = [System.Net.WebUtility]::HtmlEncode($item.Title)
            $safeState  = [System.Net.WebUtility]::HtmlEncode($item.CurrentState)
            $safeRemedy = [System.Net.WebUtility]::HtmlEncode($item.Remediation)
            $safeMitre  = [System.Net.WebUtility]::HtmlEncode($item.MitreID)

            $tableRows += @"
            <tr>
                <td class="mono">$($item.CheckID)</td>
                <td><span class="badge $sevClass">$($item.Severity)</span></td>
                <td>$($item.Domain)</td>
                <td><strong>$safeTitle</strong></td>
                <td class="mono">$safeMitre</td>
                <td class="state-cell">$safeState</td>
                <td class="remedy-cell">$safeRemedy</td>
            </tr>
"@
        }
    }
    else {
        $tableRows = @"
        <tr>
            <td colspan="7" style="text-align:center; padding: 2rem; color: #10b981; font-weight: bold;">
                &#10004; All audited controls passed baseline checks. Zero misconfigurations detected.
            </td>
        </tr>
"@
    }

    # Pure ASCII HTML entities (&#10004; = Checkmark, &#9888; = Warning)
    $privBadge = if ($ElevatedScan) {
        "<span style='color:#10b981;'>&#10004; Administrator (Elevated)</span>"
    }
    else {
        "<span style='color:#f59e0b;'>&#9888; Standard User (Partial Visibility)</span>"
    }

    $scanTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    # Assemble complete HTML document (IMPORTANT: Keep "@ at column 0 with no leading spaces)
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Posture Report - $env:COMPUTERNAME</title>
    <style>
        :root {
            --bg-dark: #090a0c;
            --card-bg: #262b33;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #0e1013;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }
        header h1 { font-size: 1.75rem; font-weight: 700; color: #38bdf8; }
        .meta-info { text-align: right; font-size: 0.875rem; color: var(--text-muted); }
        .meta-info span { display: block; }
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }
        .kpi-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 1.25rem;
        }
        .kpi-title { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
        .kpi-value { font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }
        .severity-breakdown { display: flex; gap: 0.75rem; margin-top: 0.5rem; font-size: 0.85rem; flex-wrap: wrap; }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.65rem;
            font-size: 0.75rem;
            font-weight: 700;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge-high     { background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
        .badge-medium   { background-color: rgba(234, 179, 8, 0.2);  color: #facc15; border: 1px solid #eab308; }
        .badge-low      { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .badge-informational { background-color: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid #64748b; }
        .table-container {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            overflow-x: auto;
        }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
        th {
            background-color: #0f172a;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        td { padding: 1rem; border-bottom: 1px solid var(--border-color); vertical-align: top; }
        tr:last-child td { border-bottom: none; }
        tr:hover { background-color: rgba(255, 255, 255, 0.02); }
        .mono { font-family: "Cascadia Code", Consolas, monospace; font-size: 0.82rem; color: #cbd5e1; white-space: nowrap; }
        .state-cell { color: #cbd5e1; font-size: 0.85rem; }
        .remedy-cell { color: #0baf34; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>WinBASH Security Audit Report</h1>
                <p style="color: var(--text-muted); font-size: 0.9rem;">Windows Security Assessment. A passion project made by Sebastian Castillo. </p>
            </div>
            <div class="meta-info">
                <span><strong>Host:</strong> $env:COMPUTERNAME</span>
                <span><strong>Timestamp:</strong> $scanTime</span>
                <span><strong>Execution Context:</strong> $privBadge</span>
            </div>
        </header>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Overall Risk Rating</div>
                <div class="kpi-value" style="color: $ratingColor;">$RiskRating</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Posture Deficit Score</div>
                <div class="kpi-value">$TotalRiskScore</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Total Findings</div>
                <div class="kpi-value">$($Findings.Count)</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Severity Breakdown</div>
                <div class="severity-breakdown">
                    <span class="badge badge-critical">Crit: $critCount</span>
                    <span class="badge badge-high">High: $highCount</span>
                    <span class="badge badge-medium">Med: $medCount</span>
                    <span class="badge badge-low">Low: $lowCount</span>
                </div>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Severity</th>
                        <th>Domain</th>
                        <th>Finding Title</th>
                        <th>MITRE ATT&amp;CK&reg;</th>
                        <th>Current State</th>
                        <th>Recommended Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    $tableRows
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "[+] Styled HTML dashboard saved to: $OutputPath" -ForegroundColor Green
}
