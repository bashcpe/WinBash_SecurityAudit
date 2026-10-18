<#
.SYNOPSIS
    Module 5: User & Group Hygiene Audit
#>
function Invoke-UserAndGroupHygieneAudit {
    [CmdletBinding()]
    param()
    Write-Verbose "[Module 5] Auditing UAC settings, Guest status, and local admin memberships..."

    # 5A. User Account Control (UAC) Status
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $enableLua = (Get-ItemProperty -Path $uacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    $consentBehavior = (Get-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin

    if ($enableLua -ne 1) {
        Add-AuditFinding -CheckID "IAM-01" `
            -Domain "User & Group Hygiene" `
            -Title "User Account Control (EnableLUA) Disabled" `
            -Severity "High" `
            -MitreID "T1548.002 (Bypass User Account Control)" `
            -CurrentState "EnableLUA = $enableLua" `
            -Remediation "Set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to 1."
    }
    elseif ($consentBehavior -eq 0) {
        Add-AuditFinding -CheckID "IAM-02" `
            -Domain "User & Group Hygiene" `
            -Title "UAC Admin Elevation Prompt Set to 'Elevate Without Prompting'" `
            -Severity "Medium" `
            -MitreID "T1548.002 (Bypass User Account Control)" `
            -CurrentState "ConsentPromptBehaviorAdmin = 0" `
            -Remediation "Set ConsentPromptBehaviorAdmin to 2 (Always notify) or 5 (Prompt for non-Windows binaries)."
    }

    # 5B. Local Administrators Group Sprawl
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        if ($admins.Count -gt 2) {
            $memberNames = ($admins.Name) -join ", "
            Add-AuditFinding -CheckID "IAM-03" `
                -Domain "User & Group Hygiene" `
                -Title "Excessive Local Administrator Accounts" `
                -Severity "Low" `
                -MitreID "T1078.003 (Valid Accounts: Local Accounts)" `
                -CurrentState "Found $($admins.Count) members in Administrators: $memberNames" `
                -Remediation "Review and prune unnecessary accounts from the local Administrators group."
        }
    }
    catch {
        Write-Verbose "Could not enumerate local Administrators group: $_"
    }

    # 5C. Built-In Guest Account Enabled Check
    try {
        $guestAcct = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if ($guestAcct.Enabled) {
            Add-AuditFinding -CheckID "IAM-04" `
                -Domain "User & Group Hygiene" `
                -Title "Built-in Local Guest Account Enabled" `
                -Severity "Medium" `
                -MitreID "T1078.003 (Valid Accounts: Local Accounts)" `
                -CurrentState "Local user 'Guest' Enabled = True" `
                -Remediation "Disable the Guest account via 'Disable-LocalUser -Name Guest'."
        }
    }
    catch {
        Write-Verbose "Could not query Guest account status: $_"
    }
}
