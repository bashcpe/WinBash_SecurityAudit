<#
.SYNOPSIS
    Module 3: Credential & Artifact Protection Audit
#>
function Invoke-CredentialProtectionAudit {
    [CmdletBinding()]
    param()
    Write-Verbose "[Module 3] Auditing LSA protection, WDigest, and deployment artifacts..."

    # 3A. LSA Protection (RunAsPPL)
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $pplVal = (Get-ItemProperty -Path$lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    if ($pplVal -ne 1 -and$pplVal -ne 2) {
        Add-AuditFinding -CheckID "CRED-01" `
            -Domain "Credential Protection" `
            -Title "LSASS Protected Process Light (RunAsPPL) Not Enforced" `
            -Severity "High" `
            -MitreID "T1003.001 (OS Credential Dumping: LSASS Memory)" `
            -CurrentState "RunAsPPL value is '$pplVal' (Expected: 1 or 2)." `
            -Remediation "Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL to 1."
    }

    # 3B. WDigest Cleartext Credential Caching
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if (Test-Path $wdigestPath) {
        $useLogonCred = (Get-ItemProperty -Path$wdigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
        if ($useLogonCred -eq 1) {
            Add-AuditFinding -CheckID "CRED-02" `
                -Domain "Credential Protection" `
                -Title "WDigest Cleartext Password Caching Enabled" `
                -Severity "Critical" `
                -MitreID "T1003.001 (OS Credential Dumping: LSASS Memory)" `
                -CurrentState "UseLogonCredential = 1" `
                -Remediation "Set HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential to 0."
        }
    }

    # 3C. Residual Unattended Installation Files (Existence Check Only)
    $unattendLocations = @(
        "$env:windir\Panther\Unattend.xml",
        "$env:windir\Panther\Autounattend.xml",
        "$env:windir\System32\Sysprep\unattend.xml",
        "$env:windir\System32\Sysprep\Panther\unattend.xml"
    )
    foreach ($file in $unattendLocations) {
        if (Test-Path $file) {
            Add-AuditFinding -CheckID "CRED-03" `
                -Domain "Credential Protection" `
                -Title "Residual Unattended Deployment File Present" `
                -Severity "Medium" `
                -MitreID "T1552.001 (Unsecured Credentials: Credentials In Files)" `
                -CurrentState "Deployment configuration file found at: $file" `
                -Remediation "Inspect and securely delete residual deployment XML files after provisioning."
        }
    }

    # 3D. Excessive Cached Domain Logons
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $cachedLogons = (Get-ItemProperty -Path$winlogonPath -Name "CachedLogonsCount" -ErrorAction SilentlyContinue).CachedLogonsCount
    if ([int]$cachedLogons -gt 2) {
        Add-AuditFinding -CheckID "CRED-04" `
            -Domain "Credential Protection" `
            -Title "Excessive Cached Domain Logon Count" `
            -Severity "Low" `
            -MitreID "T1003.005 (Cached Domain Credentials)" `
            -CurrentState "CachedLogonsCount is set to $cachedLogons (CIS Benchmark recommends <= 2 on workstations, 0 on servers)." `
            -Remediation "Reduce 'Interactive logon: Number of previous logons to cache' via Group Policy."
    }
}
