#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Retrieve all hosts with Falcon installed, append their installed applications, then output to Json
.DESCRIPTION
Requires "Hosts: Read" and "Falcon Discover: Read"
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Hostname
CrowdStrike API hostname
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,ValueFromPipelineByPropertyName,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(Mandatory,ValueFromPipelineByPropertyName,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(ValueFromPipelineByPropertyName,Position=3)]
  [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
  [string]$Hostname
)
begin {
  function Add-AppList ([object[]]$HostObj,[object[]]$AppObj) {
    foreach ($Member in $HostObj) {
      # Append installed applications to final host output
      $Member.PSObject.Properties.Add((New-Object PSNoteProperty('applications',(@($AppObj).Where({
        $_.host.aid -eq $Member.device_id })))))
      Write-Host "Matched $(($Member.applications.id | Measure-Object).Count) applications to host $(
        $Member.device_id)."
      $Member
    }
  }
  # Request authorization token
  $Token = @{}
  @('ClientId','ClientSecret','Hostname').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  Request-FalconToken @Token
  [string]$Json = "hosts_and_applications_$(Get-Date -Format FileDateTime).json"
}
process {
  # Retrieve all hosts and their details
  Write-Host "Start $(Get-Date -Format o)"
  $HostList = Get-FalconHost -Detailed -All
  $HostTotal = ($HostList.device_id | Measure-Object).Count
  Write-Host "Retrieved $HostTotal host results."
  $Output = for ($i=0; $i -lt $HostTotal; $i+=100) {
    # Check total count of applications using group of 100 ids
    [object[]]$Group = @($HostList)[$i..($i+99)]
    [string]$Filter = "host.aid:[$((@($Group).foreach{ "'$($_.device_id)'" }) -join ',')]"
    [int32]$AppTotal = Get-FalconAsset -Filter $Filter -Application -Total
    if ($AppTotal -lt 10000) {
      # Request all 100 hosts if total application results are less than 10,000
      Write-Host "[$i of $HostTotal] Requesting $AppTotal apps for hosts $($Group[0].device_id) to $(
        $Group[-1].device_id)..."
      Add-AppList $Group (Get-FalconAsset -Filter $Filter -Application -Detailed -Include host_info -All)
    } else {
      for ($i2=0; $i2 -lt ($Group.device_id | Measure-Object).Count; $i2+=20) {
        # Break group of 100 into groups of 20 to stay under 10,000 results
        [object[]]$SubGroup = @($Group)[$i2..($i2+19)]
        [string]$SubFilter = "host.aid:[$((@($SubGroup).foreach{ "'$($_.device_id)'" }) -join ',')]"
        [int32]$SubTotal = Get-FalconAsset -Filter $SubFilter -Application -Total
        Write-Host "[$($i + $i2) of $HostTotal] Requesting $SubTotal apps for hosts $(
          $SubGroup[0].device_id) to $($SubGroup[-1].device_id)..."
        Add-AppList $SubGroup (Get-FalconAsset -Filter $SubFilter -Application -Detailed -Include host_info -All)
      }
    }
  }
  $Output | ConvertTo-Json -Depth 32 > $Json
  Write-Host "End $(Get-Date -Format o)"
}
end { if (Test-Path $Json) { Get-ChildItem $Json | Select-Object FullName,Length,LastWriteTime }}