#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Create a CSV in the local directory containing on-demand scan results matching a hostname search result
.DESCRIPTION
Requires 'Hosts: Read' and 'On-demand scans (ODS): Read'.
.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.PARAMETER Hostname
Hostname value, used with authorization token request [default: https://api.crowdstrike.com]
.PARAMETER MemberCid
Optional child CID, if requesting an authorization token for a single child CID
.PARAMETER ScanTarget
Hostname of device to output on-demand scan results
.EXAMPLE
.\export-scans-by-hostname.ps1 -ClientId abc -ClientSecret def -ScanTarget my_hostname
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(Position=3)]
  [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
  [string]$Hostname,
  [Parameter(Position=4)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$MemberCid,
  [Parameter(Mandatory,Position=5)]
  [string]$ScanTarget
)
begin {
  # Build hashtable for authorization token request
  $Token = @{}
  @('ClientId','ClientSecret','Hostname','MemberCid').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
}
process {
  try {
    # Request an authorization token from the Falcon APIs
    Request-FalconToken @Token
    if ((Test-FalconToken).Token -eq $true) {
      # Find 'device_id' matching $ScanTarget and assemble CSV name
      [string]$HostId = Get-FalconHost -Filter "hostname:'$ScanTarget'" -Sort last_seen.desc -Limit 1
      if (!$HostId) { throw "No device found matching '$ScanTarget'." }
      [string]$OutputFile = Join-Path (Get-Location).Path ('scan_results_for_{0}_{1}.csv' -f $HostId,(
        Get-Date -Format FileDateTime))
      # Retrieve scan results and export to CSV
      Get-FalconScan -Detailed -All | Where-Object { $_.hosts -contains $HostId } | Select-Object @{l='scan_id';
        e={$_.id}},@{l='device_id';e={$_.hosts -join ','}},status,initiated_from,@{l='file_paths';e={
        $_.file_paths -join ','}},@{l='scanned';e={$_.filecount.scanned}},@{l='malicious';e={
        $_.filecount.malicious}},@{l='quarantined';e={$_.filecount.quarantined}},@{l='skipped';e={
        $_.filecount.skipped}},@{l='traversed';e={$_.filecount.traversed}},scan_started_on,scan_completed_on |
        Export-Csv $OutputFile -NoTypeInformation -Append
    }
  } catch {
    throw $_
  } finally {
    # Silently revoke active authorization token
    if ((Test-FalconToken).Token -eq $true) { [void](Revoke-FalconToken) }
  }
}
end { if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }}