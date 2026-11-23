# Hck Windows Security Audit — read-only local checks (no exploits / no remoting).
# Output: JSON object with a "checks" array to -OutFile / stdout.
param(
    [Parameter(Mandatory = $false)]
    [string]$OutFile = ""
)

$ErrorActionPreference = "Continue"
$checks = @()

function Add-Check {
    param(
        [string]$Id,
        [string]$Title,
        [ValidateSet("pass", "fail", "warn", "info")]
        [string]$Status,
        [ValidateSet("info", "low", "medium", "high", "critical")]
        [string]$Severity,
        [string]$Detail
    )
    $script:checks += [ordered]@{
        id       = $Id
        title    = $Title
        status   = $Status
        severity = $Severity
        detail   = $Detail
    }
}

# 1) Windows Defender realtime
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.RealTimeProtectionEnabled) {
        Add-Check "defender.realtime" "Windows Defender Real-time Protection" "pass" "info" "Enabled"
    } else {
        Add-Check "defender.realtime" "Windows Defender Real-time Protection" "fail" "high" "Disabled"
    }
    if ($mp.AntivirusEnabled) {
        Add-Check "defender.av" "Windows Defender Antivirus" "pass" "info" "Enabled"
    } else {
        Add-Check "defender.av" "Windows Defender Antivirus" "fail" "high" "Disabled"
    }
} catch {
    Add-Check "defender.realtime" "Windows Defender status" "warn" "medium" "Unable to query: $($_.Exception.Message)"
}

# 2) Firewall profiles
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($p in $profiles) {
        $name = $p.Name
        if ($p.Enabled) {
            Add-Check "firewall.$name" "Firewall profile $name" "pass" "info" "Enabled"
        } else {
            Add-Check "firewall.$name" "Firewall profile $name" "fail" "high" "Disabled"
        }
    }
} catch {
    Add-Check "firewall" "Firewall profiles" "warn" "medium" "Unable to query: $($_.Exception.Message)"
}

# 3) UAC
try {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop
    if ([int]$uac.EnableLUA -eq 1) {
        Add-Check "uac.enable" "User Account Control (EnableLUA)" "pass" "info" "Enabled"
    } else {
        Add-Check "uac.enable" "User Account Control (EnableLUA)" "fail" "high" "Disabled"
    }
} catch {
    Add-Check "uac.enable" "User Account Control" "warn" "low" "Unable to query registry"
}

# 4) SMBv1
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    if ($smb.EnableSMB1Protocol) {
        Add-Check "smb.v1" "SMBv1 protocol" "fail" "high" "SMBv1 is enabled"
    } else {
        Add-Check "smb.v1" "SMBv1 protocol" "pass" "info" "SMBv1 disabled"
    }
} catch {
    Add-Check "smb.v1" "SMBv1 protocol" "warn" "low" "Unable to query SMB configuration"
}

# 5) RDP Network Level Authentication
try {
    $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction Stop
    if ([int]$nla.UserAuthentication -eq 1) {
        Add-Check "rdp.nla" "RDP Network Level Authentication" "pass" "info" "NLA required"
    } else {
        Add-Check "rdp.nla" "RDP Network Level Authentication" "fail" "medium" "NLA not required"
    }
} catch {
    Add-Check "rdp.nla" "RDP NLA" "info" "info" "RDP settings not readable (service may be absent)"
}

# 6) AutoAdminLogon
try {
    $aal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    if ($null -ne $aal -and [string]$aal.AutoAdminLogon -eq "1") {
        Add-Check "winlogon.autoadmin" "AutoAdminLogon" "fail" "high" "AutoAdminLogon is enabled"
    } else {
        Add-Check "winlogon.autoadmin" "AutoAdminLogon" "pass" "info" "Not enabled"
    }
} catch {
    Add-Check "winlogon.autoadmin" "AutoAdminLogon" "warn" "low" "Unable to query"
}

# 7) BitLocker (informational)
try {
    $bl = Get-BitLockerVolume -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $bl) {
        Add-Check "bitlocker" "BitLocker" "warn" "medium" "No volumes returned"
    } elseif ($bl.ProtectionStatus -eq "On") {
        Add-Check "bitlocker" "BitLocker" "pass" "info" "Protection on for $($bl.MountPoint)"
    } else {
        Add-Check "bitlocker" "BitLocker" "fail" "medium" "Protection not on for $($bl.MountPoint)"
    }
} catch {
    Add-Check "bitlocker" "BitLocker" "info" "info" "BitLocker cmdlets unavailable or access denied"
}

# 8) Execution policy (current user) — informational
try {
    $ep = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction Stop
    Add-Check "ps.execution_policy" "PowerShell ExecutionPolicy (CurrentUser)" "info" "info" "Policy=$ep"
} catch {
    Add-Check "ps.execution_policy" "PowerShell ExecutionPolicy" "warn" "low" "Unable to query"
}

$result = [ordered]@{
    scanner = "windows_host_audit"
    host    = $env:COMPUTERNAME
    os      = [System.Environment]::OSVersion.VersionString
    checks  = $checks
}

$json = $result | ConvertTo-Json -Depth 6
if ($OutFile -ne "") {
    Set-Content -Path $OutFile -Value $json -Encoding UTF8
}
Write-Output $json
