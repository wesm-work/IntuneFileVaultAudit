<#
.SYNOPSIS
  One-off Intune audit: verify FileVault recovery key escrow (macOS).

.DESCRIPTION
  Queries Intune for macOS managed devices and attempts to retrieve each device’s
  FileVault recovery key using Microsoft Graph getFileVaultKey (beta).
  The script does NOT export or log recovery key values—only whether the key is retrievable.

.REQUIREMENTS
  - Microsoft.Graph + Microsoft.Graph.Beta PowerShell modules
  - Delegated admin sign-in with these scopes:
      DeviceManagementManagedDevices.Read.All
      DeviceManagementManagedDevices.PrivilegedOperations.All  (required for key retrieval)
  - Uses Microsoft Graph /beta for getFileVaultKey.

.OUTPUTS
  - CSV report containing: device name, serial, UPN, owner type, escrow status, and notes.
#>

[CmdletBinding()]
param(
  # Folder for the CSV output (defaults to current directory)
  [Parameter(Mandatory = $false)]
  [string]$OutputDirectory = ".",

  # Include personal/BYOD devices in the report (marked as not accessible)
  [Parameter(Mandatory = $false)]
  [switch]$IncludePersonalDevices = $true,

  # If set, suppress progress output
  [Parameter(Mandatory = $false)]
  [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
  param([string]$Message)
  if (-not $Quiet) { Write-Host $Message -ForegroundColor Cyan }
}

function Write-Warn {
  param([string]$Message)
  if (-not $Quiet) { Write-Host $Message -ForegroundColor Yellow }
}

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    throw "Required module '$Name' is not installed. Install with: Install-Module $Name -Scope CurrentUser"
  }
}

function Connect-GraphForAudit {
  Write-Info "Checking prerequisites..."
  Ensure-Module -Name "Microsoft.Graph"
  Ensure-Module -Name "Microsoft.Graph.Beta"

  Import-Module Microsoft.Graph -ErrorAction Stop
  Import-Module Microsoft.Graph.Beta -ErrorAction Stop

  $scopes = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All"
  )

  Write-Info "Connecting to Microsoft Graph (interactive)..."
  Connect-MgGraph -Scopes $scopes | Out-Null

  # getFileVaultKey is exposed via Graph beta
  Select-MgProfile -Name "beta"
  Write-Info "Connected to Graph (beta profile selected)."
}

function Get-MacManagedDevices {
  Write-Info "Retrieving macOS devices from Intune..."
  # Use -Property to reduce payload and keep response fast/consistent
  $devices = Get-MgBetaDeviceManagementManagedDevice -All `
    -Filter "operatingSystem eq 'macOS'" `
    -Property "id,deviceName,serialNumber,userPrincipalName,managedDeviceOwnerType,lastSyncDateTime"

  Write-Info ("Found {0} macOS devices." -f $devices.Count)
  return $devices
}

function Invoke-WithRetry {
  param(
    [scriptblock]$Operation,
    [int]$MaxAttempts = 3,
    [int]$InitialDelaySeconds = 2
  )

  $attempt = 1
  $delay = $InitialDelaySeconds

  while ($true) {
    try {
      return & $Operation
    }
    catch {
      $msg = $_.Exception.Message

      # Simple throttling retry (429)
      if ($msg -match "429|Too Many Requests") {
        if ($attempt -ge $MaxAttempts) { throw }
        Start-Sleep -Seconds $delay
        $attempt++
        $delay *= 2
        continue
      }

      throw
    }
  }
}

function Test-FileVaultKeyEscrowed {
  param(
    [Parameter(Mandatory=$true)][string]$ManagedDeviceId
  )

  # IMPORTANT: Do not output key value. We only check presence.
  $resp = Invoke-WithRetry -Operation {
    Get-MgBetaDeviceManagementManagedDeviceFileVaultKey -ManagedDeviceId $ManagedDeviceId
  }

  if ($resp -and $resp.Value -and $resp.Value.Trim().Length -gt 0) { return $true }
  return $false
}

# --------------------------- MAIN ---------------------------

try {
  Connect-GraphForAudit
  $macDevices = Get-MacManagedDevices

  Write-Info "Auditing FileVault key escrow status (no keys will be exported)..."

  $results = foreach ($d in $macDevices) {
    $ownerType = $d.ManagedDeviceOwnerType
    $status = "Unknown"
    $hasKey = $false
    $note = $null

    if ($ownerType -eq "personal") {
      if (-not $IncludePersonalDevices) { continue }
      $status = "Personal device (key not accessible to admins)"
      $hasKey = $false
    }
    else {
      try {
        $hasKey = Test-FileVaultKeyEscrowed -ManagedDeviceId $d.Id
        $status = if ($hasKey) { "Key retrievable (escrowed)" } else { "Not found / not escrowed" }
      }
      catch {
        $msg = $_.Exception.Message
        $note = $msg

        if ($msg -match "403|Forbidden") {
          $status = "Forbidden (permissions/RBAC)"
        }
        elseif ($msg -match "404|NotFound") {
          $status = "Not found / not escrowed"
        }
        elseif ($msg -match "429|Too Many Requests") {
          $status = "Throttled (rerun or increase retries)"
        }
        else {
          $status = "Error (see Note)"
        }
      }
    }

    [pscustomobject]@{
      DeviceName             = $d.DeviceName
      SerialNumber           = $d.SerialNumber
      UserPrincipalName      = $d.UserPrincipalName
      OwnerType              = $ownerType
      HasFileVaultKeyEscrowed= $hasKey
      Status                 = $status
      LastSyncDateTime       = $d.LastSyncDateTime
      ManagedDeviceId        = $d.Id
      Note                   = $note
    }
  }

  # Summary (nice for leadership)
  $total    = $results.Count
  $escrowed = ($results | Where-Object { $_.HasFileVaultKeyEscrowed }).Count
  $personal = ($results | Where-Object { $_.OwnerType -eq "personal" }).Count
  $missing  = ($results | Where-Object { -not $_.HasFileVaultKeyEscrowed -and $_.OwnerType -ne "personal" }).Count

  Write-Host ""
  Write-Host "Summary" -ForegroundColor Green
  Write-Host ("  Total macOS devices:            {0}" -f $total)
  Write-Host ("  Corporate w/ key escrowed:      {0}" -f $escrowed)
  Write-Host ("  Personal (not accessible):      {0}" -f $personal)
  Write-Host ("  Corporate missing/failed:       {0}" -f $missing)
  Write-Host ""

  # Export
  $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $outPath = Join-Path $OutputDirectory ("FileVaultKeyAudit-{0}.csv" -f $timestamp)

  $results |
    Sort-Object HasFileVaultKeyEscrowed, DeviceName |
    Export-Csv -NoTypeInformation -Path $outPath

  Write-Host ("Saved report: {0}" -f $outPath) -ForegroundColor Green
}
finally {
  # Disconnect to be neat in shared terminals
  Disconnect-MgGraph | Out-Null
}
