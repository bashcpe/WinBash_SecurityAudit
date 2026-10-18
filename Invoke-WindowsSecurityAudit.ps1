<#
.SYNOPSIS
    Orchestrator for WinBASH Security Posture Audit Engine. Loads all audit modules and reporting modules, executes them, and generates JSON/HTML reports.
#>

[CmdletBinding()]
param (
    [switch]$ExportJson,
    [string]$JsonOutputPath = "$PSScriptRoot\reports\security_audit_report.json",

    [switch]$ExportHtml,
    [string]$HtmlOutputPath = "$PSScriptRoot\reports\security_audit_report.html",

    [switch]$LaunchHtml
)

# 1. GLOBAL STATE & HELPER INITIALIZATION
$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-AuditFinding {
    param (
        [Parameter(Mandatory)] [string]$CheckID,
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [string]$Title,
        [Parameter(Mandatory)] [ValidateSet("Informational", "Low", "Medium", "High", "Critical")] [string]$Severity,
        [Parameter(Mandatory)] [string]$MitreID,
        [Parameter(Mandatory)] [string]$CurrentState,
        [Parameter(Mandatory)] [string]$Remediation
    )

    $weightMap = @{
        "Informational" = 0
        "Low"           = 2
        "Medium"        = 5
        "High"          = 8
        "Critical"      = 10
    }

    $script:Findings.Add([PSCustomObject]@{
        CheckID      = $CheckID
        Domain       = $Domain
        Title        = $Title
        Severity     = $Severity
        ScoreWeight  = $weightMap[$Severity]
        MitreID      = $MitreID
        CurrentState = $CurrentState
        Remediation  = $Remediation
        Timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    })
}

# 2. ROOT-SCOPE MODULE LOADER
Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "   WINDOWS LOCAL SECURITY POSTURE & HARDENING AUDIT ENGINE" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$auditsDir    = "$PSScriptRoot\modules\audits"
$reportingDir = "$PSScriptRoot\modules\reporting"

# Ensure output directory exists if exporting
if (($ExportJson) -or ($ExportHtml)) {
    $reportsFolder = "$PSScriptRoot\reports"
    if (-not (Test-Path -Path:($reportsFolder))) {
        New-Item -ItemType Directory -Path:($reportsFolder) -Force | Out-Null
    }
}

# Load Reporting Modules into Root Scope
if (Test-Path -Path:($reportingDir)) {
    Get-ChildItem -Path "$reportingDir\*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Verbose "Importing reporting module: $($_.Name)"
        . ($_.FullName)
    }
} else {
    Write-Warning "Reporting directory not found at: $reportingDir"
}

# Load Audit Modules into Root Scope
if (Test-Path -Path:($auditsDir)) {
    Get-ChildItem -Path "$auditsDir\*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Verbose "Importing audit module: $($_.Name)"
        . ($_.FullName)
    }
} else {
    Throw "Critical Error: Audit modules directory missing at '$auditsDir'."
}

# 3. MAIN EXECUTION ENGINE
function Start-SecurityPostureAudit {
    # Check privilege context
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not ($isAdmin)) {
        Write-Warning "Running without Administrator privileges. Some registry and service checks may return incomplete results.`n"
    }

    # Discover and invoke all loaded Invoke-*Audit functions automatically
    $auditFunctions = @(Get-Command -Name "Invoke-*Audit" -CommandType Function |
        Where-Object { $_.Name -ne "Invoke-WindowsSecurityAudit" })

    Write-Host "[*] Executing $($auditFunctions.Count) loaded audit modules..." -ForegroundColor Gray

    $auditFunctions | ForEach-Object {
        $func =$_
        try {
            & ($func.Name)
        }
        catch {
            Write-Warning "Error executing module $($func.Name):$_"
        }
    }

    # Calculate Aggregate Risk Metrics
    $totalRiskScore = ($script:Findings | Measure-Object -Property ScoreWeight -Sum).Sum
    if (-not ($totalRiskScore)) {$totalRiskScore = 0 }

    $riskRating = switch ($totalRiskScore) {
        { $_ -eq 0 }  { "Optimal (Hardened)"; break }
        { $_ -le 10 } { "Low Risk"; break }
        { $_ -le 25 } { "Moderate Risk"; break }
        default       { "High Exposure" }
    }

    # Console Summary Output
    Write-Host "`n--- AUDIT SUMMARY ---" -ForegroundColor Yellow
    Write-Host "Host Name                        : $env:COMPUTERNAME"
    Write-Host "Total Misconfigurations Detected : $($script:Findings.Count)"
    Write-Host "Cumulative Risk Deficit Score    : $totalRiskScore ($riskRating)`n"

    if ($script:Findings.Count -gt 0) {$script:Findings |
            Sort-Object ScoreWeight -Descending |
            Select-Object CheckID, Severity, Domain, Title, MitreID |
            Format-Table -AutoSize
    }
    else {
        Write-Host "[+] All audited controls passed baseline checks." -ForegroundColor Green
    }

    # Export JSON Report
    if ($ExportJson) {$reportPayload = [PSCustomObject]@{
            HostName       = $env:COMPUTERNAME
            ScanTimestamp  = (Get-Date).ToString("o")
            ElevatedScan   = $isAdmin
            TotalRiskScore = $totalRiskScore
            RiskRating     = $riskRating
            Findings       = $script:Findings
        }
        $reportPayload | ConvertTo-Json -Depth 5 | Out-File -FilePath:($JsonOutputPath) -Encoding utf8
        Write-Host "[+] Detailed JSON report saved to: $JsonOutputPath" -ForegroundColor Green
    }

    # Export HTML Dashboard Report
    if ($ExportHtml) {
        if (Get-Command -Name "Export-AuditHtmlReport" -ErrorAction SilentlyContinue) {
            Export-AuditHtmlReport -Findings:($script:Findings) `
                -TotalRiskScore:($totalRiskScore) `
                -RiskRating:($riskRating) `
                -ElevatedScan:($isAdmin) `
                -OutputPath:($HtmlOutputPath)

            if (($LaunchHtml) -and (Test-Path -Path:($HtmlOutputPath))) {
                Invoke-Item -Path:($HtmlOutputPath)
            }
        }
        else {
            Write-Error "Export-AuditHtmlReport function is not loaded. Verify modules\reporting\Export-AuditHtmlReport.ps1 exists."
        }
    }
}

# Run the orchestrator
Start-SecurityPostureAudit