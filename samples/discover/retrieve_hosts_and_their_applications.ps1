#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Retrieve all hosts with Falcon installed and append their installed applications to final output
.DESCRIPTION
Requires "Hosts: Read" and "Falcon Discover: Read"
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
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
  # Request authorization token
  $Token = @{}
  @('ClientId','ClientSecret','Hostname').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  Request-FalconToken @Token
}
process {
  # Retrieve all hosts and their details
  $HostList = Get-FalconHost -Detailed -All
  for ($i=0; $i -lt ($HostList.device_id | Measure-Object).Count; $i+=100) {
    # In groups of 100 ids, retrieve list of installed applications
    [string[]]$IdGroup = @($HostList.device_id)[$i..($i+99)]
    $Param = @{
      Filter = "host.aid:[$((@($IdGroup).foreach{ "'$_'"}) -join ',')]"
      Application = $true
      Detailed = $true
      All = $true
    }
    $AppList = Get-FalconAsset @Param
    foreach ($Id in $IdGroup) {
      @($HostList).Where({ $_.device_id -eq $Id }).foreach{
        # Append installed applications to host output
        $_.PSObject.Properties.Add((New-Object PSNoteProperty('applications',(
          @($AppList).Where({ $_.host.aid -eq $Id })))))
      }
    }
  }
  $HostList
}