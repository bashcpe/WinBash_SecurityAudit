<#
.SYNOPSIS
    Module 1: System, Patch Level & Defensive Controls Audit
#>
function Invoke-SystemAndDefenseAudit {
    [CmdletBinding()]
    param()
    Write-Verbose "[Module 1] Auditing OS patching, Defender status, and PowerShell logging..."

    # 1A. Check days since last installed HotFix
    try {
        $latestHotfix = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($latestHotfix) {
            $daysSincePatch = ((Get-Date) - $latestHotfix.InstalledOn).Days
            if ($daysSincePatch -gt 60) {
                Add-AuditFinding -CheckID "SYS-01" `
                    -Domain "System & Patch Level" `
                    -Title "Outdated OS Patch Level" `
                    -Severity "Medium" `
                    -MitreID "T1068 (Exploitation for Privilege Escalation)" `
                    -CurrentState "Last hotfix ($($latestHotfix.HotFixID)) installed$daysSincePatch days ago." `
                    -Remediation "Run Windows Update or verify WSUS/Intune patch synchronization."
            }
        }
    }
    catch {
        Write-Verbose "Could not enumerate hotfixes: $_"
    }

    # 1B. Check Microsoft Defender Real-Time Protection
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mpStatus.RealTimeProtectionEnabled) {
            Add-AuditFinding -CheckID "SYS-02" `
                -Domain "System & Patch Level" `
                -Title "Defender Real-Time Protection Disabled" `
                -Severity "High" `
                -MitreID "T1562.001 (Impair Defenses: Disable or Modify Tools)" `
                -CurrentState "RealTimeProtectionEnabled = False" `
                -Remediation "Enable real-time monitoring via 'Set-MpPreference -DisableRealtimeMonitoring `$false'."
        }
    }
    catch {
        Write-Verbose "Unable to query Microsoft Defender status (third-party EDR may be installed)."
    }

    # 1C. Check PowerShell Script Block Logging
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $sbLogging = if (Test-Path $psLogPath) { (Get-ItemProperty -Path$psLogPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging } else { 0 }

    if ($sbLogging -ne 1) {
        Add-AuditFinding -CheckID "SYS-03" `
            -Domain "System & Patch Level" `
            -Title "PowerShell Script Block Logging Not Enforced" `
            -Severity "Low" `
            -MitreID "T1059.001 (Command and Scripting Interpreter: PowerShell)" `
            -CurrentState "EnableScriptBlockLogging is '$sbLogging' (Expected: 1)." `
            -Remediation "Enable 'Turn on PowerShell Script Block Logging' via Group Policy (Event ID 4104)."
    }
}
