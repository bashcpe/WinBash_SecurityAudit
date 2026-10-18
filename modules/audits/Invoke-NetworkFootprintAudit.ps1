<#
.SYNOPSIS
    Module 4: Network & Active Connection Footprinting Audit
#>
function Invoke-NetworkFootprintAudit {
    [CmdletBinding()]
    param()
    Write-Verbose "[Module 4] Auditing firewall profiles, SMB signing, and legacy protocols..."

    # 4A. Windows Firewall Profiles
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($prof in $fwProfiles) {
            if (-not $prof.Enabled) {
                Add-AuditFinding -CheckID "NET-01" `
                    -Domain "Network Footprinting" `
                    -Title "Windows Firewall Disabled ($($prof.Name) Profile)" `
                    -Severity "High" `
                    -MitreID "T1562.004 (Disable or Modify System Firewall)" `
                    -CurrentState "Profile '$($prof.Name)' Enabled state is False." `
                    -Remediation "Enable via 'Set-NetFirewallProfile -Profile $($prof.Name) -Enabled True'."
            }
        }
    }
    catch {
        Write-Verbose "Unable to query firewall profiles: $_"
    }

    # 4B. SMBv1 & SMB Signing Configuration
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smbConfig.EnableSMB1Protocol) {
            Add-AuditFinding -CheckID "NET-02" `
                -Domain "Network Footprinting" `
                -Title "Legacy SMBv1 Protocol Enabled" `
                -Severity "High" `
                -MitreID "T1210 (Exploitation of Remote Services)" `
                -CurrentState "EnableSMB1Protocol = True" `
                -Remediation "Disable via 'Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force'."
        }

        if (-not $smbConfig.RequireSecuritySignature) {
            Add-AuditFinding -CheckID "NET-03" `
                -Domain "Network Footprinting" `
                -Title "SMB Server Signing Not Required" `
                -Severity "Medium" `
                -MitreID "T1557.001 (Adversary-in-the-Middle: SMB Relay)" `
                -CurrentState "RequireSecuritySignature = False" `
                -Remediation "Enforce SMB signing via 'Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force'."
        }
    }
    catch {
        Write-Verbose "Unable to query SMB configuration: $_"
    }

    # 4C. LLMNR (Link-Local Multicast Name Resolution) Status
    $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $enableMulticast = if (Test-Path $dnsClientPath) { (Get-ItemProperty -Path$dnsClientPath -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast } else { 1 }

    if ($enableMulticast -ne 0) {
        Add-AuditFinding -CheckID "NET-04" `
            -Domain "Network Footprinting" `
            -Title "LLMNR Multicast Name Resolution Enabled" `
            -Severity "Medium" `
            -MitreID "T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)" `
            -CurrentState "EnableMulticast is '$enableMulticast' (Expected: 0 to disable LLMNR)." `
            -Remediation "Enable 'Turn off multicast name resolution' in Group Policy under Computer Configuration > Administrative Templates > Network > DNS Client."
    }
}
