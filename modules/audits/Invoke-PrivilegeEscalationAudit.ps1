<#
.SYNOPSIS
    Module 2: Local Privilege Escalation (LPE) Misconfiguration Audit
#>
function Invoke-PrivilegeEscalationAudit {
    [CmdletBinding()]
    param()
    Write-Verbose "[Module 2] Auditing service paths and installer elevation policies..."

    # 2A. Unquoted Service Paths
    $unquotedServices = Get-CimInstance -ClassName Win32_Service | Where-Object {
        $_.PathName -and$_.PathName -notmatch '^"' -and
        $_.PathName -notmatch '(?i)^[a-z]:\\windows\\system32' -and
        ($_.PathName -split '\.exe')[0] -match '\s'
    }

    foreach ($svc in $unquotedServices) {
        Add-AuditFinding -CheckID "LPE-01" `
            -Domain "Privilege Escalation" `
            -Title "Unquoted Service Binary Path: $($svc.Name)" `
            -Severity "Medium" `
            -MitreID "T1574.009 (Path Interception by Unquoted Path)" `
            -CurrentState "Service '$($svc.Name)' (StartMode: $($svc.StartMode)) path: $($svc.PathName)" `
            -Remediation "Wrap the ImagePath registry value under HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name) in double quotes."
    }

    # 2B. AlwaysInstallElevated Registry Policy
    $hklmMsi = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $hkcuMsi = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"

    $lmVal = if (Test-Path $hklmMsi) { (Get-ItemProperty -Path$hklmMsi -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated } else { 0 }
    $cuVal = if (Test-Path $hkcuMsi) { (Get-ItemProperty -Path$hkcuMsi -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated } else { 0 }

    if ($lmVal -eq 1 -and$cuVal -eq 1) {
        Add-AuditFinding -CheckID "LPE-02" `
            -Domain "Privilege Escalation" `
            -Title "AlwaysInstallElevated Policy Enabled" `
            -Severity "Critical" `
            -MitreID "T1548.002 (Abuse Elevation Control Mechanism)" `
            -CurrentState "AlwaysInstallElevated is set to 1 in both HKLM and HKCU hives." `
            -Remediation "Set AlwaysInstallElevated to 0 or remove the registry keys via Group Policy."
    }

    # 2C. Modifiable Service Registry Permissions (Users/Everyone Write Access)
    $servicesRegRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $riskyPrincipals = @("Everyone", "BUILTIN\Users", "NT AUTHORITY\Authenticated Users")
    $writeRights     = [System.Security.AccessControl.RegistryRights]::WriteKey -bor [System.Security.AccessControl.RegistryRights]::FullControl

    Get-ChildItem -Path $servicesRegRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $svcKey =$_
        try {
            $acl = Get-Acl -Path$svcKey.PSPath -ErrorAction Stop
            foreach ($access in $acl.Access) {
                if ($access.IdentityReference.Value -in $riskyPrincipals -and$access.AccessControlType -eq "Allow" -and 
                    ($access.RegistryRights -band$writeRights)) {
                    
                    Add-AuditFinding -CheckID "LPE-03" `
                        -Domain "Privilege Escalation" `
                        -Title "Weak Registry Permissions on Service: $($svcKey.PSChildName)" `
                        -Severity "High" `
                        -MitreID "T1574.011 (Services Registry Permissions Weakness)" `
                        -CurrentState "Principal '$($access.IdentityReference.Value)' has '$($access.RegistryRights)' on $($svcKey.Name)." `
                        -Remediation "Restrict write permissions on HKLM:\SYSTEM\CurrentControlSet\Services\$($svcKey.PSChildName) to Administrators and SYSTEM."
                    break
                }
            }
        }
        catch { }
    }
}
