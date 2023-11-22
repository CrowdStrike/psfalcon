#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
A script template to demonstrate the request of an authorization token from the CrowdStrike Falcon APIs before
running pre-determined code against a list of child CIDs within a Falcon Flight Control environment
.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.PARAMETER Cloud
Cloud value, used with authorization token request [default: us-1]
.PARAMETER Hostname
Hostname value, used with authorization token request [default: https://api.crowdstrike.com]
.PARAMETER MemberCid
A list of one or more child CIDs to run the script against [default: all active child CIDs]
.EXAMPLE
.\dev09_multi_authorization.ps1 -ClientId abc -ClientSecret def -Cloud us-1
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
  [string[]]$MemberCid
)
begin {
  # Build hashtable for authorization token request
  $Token = @{}
  @('ClientId','ClientSecret','Hostname','Cloud').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  if (!$MemberCid) {
    Request-FalconToken @Token
    if ((Test-FalconToken).Token -eq $true) {
      # Gather available active child CIDs and silently revoke initial authorization token
      [string[]]$MemberCid = Get-FalconMemberCid -Detailed -All | Where-Object { $_.status -eq 'active' } |
        Select-Object -ExpandProperty child_cid
      [void](Revoke-FalconToken)
    }
  }
}
process {
  foreach ($Cid in $MemberCid) {
    try {
      # Request an authorization token from the Falcon APIs for each member CID
      Request-FalconToken @Token -MemberCid $Cid
      if ((Test-FalconToken).Token -eq $true) {
        # Remove example and add code to run here
        (Get-Date -Format 'yyyy-MM-dd hh:mm:ss'),"token_retrieved_for_$Cid" -join ': '
      }
    } catch {
      Write-Error $_
    } finally {
      if ((Test-FalconToken).Token -eq $true) {
         # Silently revoke active authorization token and pause to prevent rate limiting
        [void](Revoke-FalconToken)
        Start-Sleep -Seconds 5
      }
    }
  }
}