#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
A script template to demonstrate a multi-step workflow that uses Real-time Response to check for the presence of
a file on a system, and if present, isolate the device using Network Containment.
.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.PARAMETER Cloud
Cloud value, used with authorization token request [default: us-1]
.PARAMETER Hostname
Hostname value, used with authorization token request [default: https://api.crowdstrike.com]
.PARAMETER MemberCid
Optional child CID, if requesting an authorization token for a single child CID
.PARAMETER Target
Name of target CrowdStrike Falcon host
.PARAMETER Filepath
Filepath to verify for containment
.EXAMPLE
.\dev09_rtr_and_contain.ps1 -ClientId abc -ClientSecret def -Cloud us-1 -Target MY-PC -Filepath C:\test.exe
#>
[CmdletBinding(DefaultParameterSetName='Cloud')]
param(
  [Parameter(ParameterSetName='Cloud',Mandatory,Position=1)]
  [Parameter(ParameterSetName='Hostname',Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(ParameterSetName='Cloud',Mandatory,Position=2)]
  [Parameter(ParameterSetName='Hostname',Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(ParameterSetName='Cloud',Position=3)]
  [ValidateSet('us-1','us-2','us-gov-1','eu-1',IgnoreCase=$false)]
  [string]$Cloud,
  [Parameter(ParameterSetName='Hostname',Position=3)]
  [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
  [string]$Hostname,
  [Parameter(ParameterSetName='Cloud',Position=4)]
  [Parameter(ParameterSetName='Hostname',Position=4)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$MemberCid,
  [Parameter(ParameterSetName='Cloud',Mandatory,Position=5)]
  [Parameter(ParameterSetName='Hostname',Mandatory,Position=5)]
  [string]$Target,
  [Parameter(ParameterSetName='Cloud',Mandatory,Position=6)]
  [Parameter(ParameterSetName='Hostname',Mandatory,Position=6)]
  [string]$Filepath
)
begin {
  # Build hashtable for authorization token request
  $Token = @{}
  @('ClientId','ClientSecret','Hostname','Cloud','MemberCid').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
}
process {
  try {
    # Request an authorization token from the Falcon APIs
    Request-FalconToken @Token
    if ((Test-FalconToken).Token -eq $true) {
      $HostId = Get-FalconHost -Filter "hostname:['$Target']"
      if (!$HostId) { throw "Unable to find target host matching '$Target'." }

      # Define script for Real-time Response
      $Script = "Test-Path $Filepath"
      $Rtr = Invoke-FalconRtr -Command runscript -Argument ('-Raw=```{0}```' -f $Script) -HostId $HostId

      # Send containment request if 'stdout' (trimmed to remove spacing/newlines) is 'True'
      if (($Rtr.stdout).Trim() -ne 'True') {
        throw "'$Filepath' not found on '$Target'."
      } else {
        Invoke-FalconHostAction -Name contain -Id $HostId
      }
    }
  } catch {
    throw $_
  } finally {
    # Silently revoke active authorization token
    if ((Test-FalconToken).Token -eq $true) { [void](Revoke-FalconToken) }
  }
}