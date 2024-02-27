#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Create a CSV containing exceptions assigned to USB Device Control policies in a CID
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
.PARAMETER PolicyId
A list of one of more Device Control policy identifiers to target in a single CID [default: all available]
#>
[CmdletBinding()]
param(
  [Parameter(ParameterSetName='Cloud',Mandatory,Position=1)]
  [Parameter(ParameterSetName='Hostname',Mandatory,Position=1)]
  [Parameter(ParameterSetName='Cloud_MemberCid',Mandatory,Position=1)]
  [Parameter(ParameterSetName='Hostname_MemberCid',Mandatory,Position=1)]
  [Parameter(ParameterSetName='Cloud_PolicyId',Mandatory,Position=1)]
  [Parameter(ParameterSetName='Hostname_PolicyId',Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(ParameterSetName='Cloud',Mandatory,Position=2)]
  [Parameter(ParameterSetName='Hostname',Mandatory,Position=2)]
  [Parameter(ParameterSetName='Cloud_MemberCid',Mandatory,Position=2)]
  [Parameter(ParameterSetName='Hostname_MemberCid',Mandatory,Position=2)]
  [Parameter(ParameterSetName='Cloud_PolicyId',Mandatory,Position=2)]
  [Parameter(ParameterSetName='Hostname_PolicyId',Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(ParameterSetName='Cloud',Position=3)]
  [Parameter(ParameterSetName='Cloud_MemberCid',Position=3)]
  [Parameter(ParameterSetName='Cloud_PolicyId',Position=3)]
  [ValidateSet('us-1','us-2','us-gov-1','eu-1',IgnoreCase=$false)]
  [string]$Cloud,
  [Parameter(ParameterSetName='Hostname',Position=3)]
  [Parameter(ParameterSetName='Hostname_MemberCid',Position=3)]
  [Parameter(ParameterSetName='Hostname_PolicyId',Position=3)]
  [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
    'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
  [string]$Hostname,
  [Parameter(ParameterSetName='Cloud_MemberCid',Mandatory)]
  [Parameter(ParameterSetName='Hostname_MemberCid',Mandatory)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string[]]$MemberCid,
  [Parameter(ParameterSetName='Cloud_PolicyId',Mandatory)]
  [Parameter(ParameterSetName='Hostname_PolicyId',Mandatory)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string[]]$PolicyId
)
begin {
  function Write-PolicyException ([string]$String,[string[]]$PolicyId) {
    $PolicyList = if ($PolicyId) {
      # Target specific policy identifiers, if given
      Get-FalconDeviceControlPolicy -Id $PolicyId
    } else {
      if ($String) { Write-Host "Retrieving USB Device Control policies for CID '$String'..." }
      Get-FalconDeviceControlPolicy -Detailed -All
    }
    if ($PolicyList) {
      [string]$Filename = 'device_control_exceptions.csv'
      if ($String) { $Filename = $String,$Filename -join '_' }
      foreach ($i in $PolicyList) {
        # Output each exception for each class under each policy
        $i.settings.classes.exceptions | Select-Object @{l='policy_id';e={$i.id}},@{l='policy_name';e={$i.name}},
          @{l='policy_platform';e={$i.platform_name}},@{l='exception_id';e={$_.id}},class,vendor_id_decimal,
          vendor_name,product_id,product_id_decimal,product_name,serial_number,combined_id,action,match_method,
          description | Export-Csv -Path (Join-Path (Get-Location).Path $Filename) -NoTypeInformation -Append
      }
      $Filename
    }
  }
  # Set baseline token request parameters
  $Token = @{}
  @('ClientId','ClientSecret','Cloud','Hostname').foreach{
    if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
  }
  Request-FalconToken @Token
  [string[]]$MemberCid = if (!$MemberCid -and !$PolicyId) {
    # Attempt to retrieve MemberCids
    @(Get-FalconMemberCid -Detailed -All -EA 0).Where({ $_.status -eq 'active' }).child_cid
  }
}
process {
  [string[]]$OutputList = if ($MemberCid) {
    if ((Test-FalconToken).Token -eq $true) { [void](Revoke-FalconToken) }
    foreach ($Cid in $MemberCid) {
      try {
        # Authenticate with Member CID and output exceptions
        Request-FalconToken @Token -MemberCid $Cid
        if ((Test-FalconToken).Token -eq $true) { Write-PolicyException $Cid }
      } catch {
        Write-Error $_
      } finally {
        if ((Test-FalconToken).Token -eq $true) {
          # Remove authentication token and sleep to avoid rate limiting
          [void](Revoke-FalconToken)
          Start-Sleep -Seconds 5
        }
      }
    }
  } elseif ((Test-FalconToken).Token -eq $true) {
    if ($PolicyId) { Write-PolicyException -PolicyId $PolicyId } else { Write-PolicyException }
  }
}
end {
  if ($OutputList) {
    @($OutputList).foreach{ if (Test-Path $_) { Get-ChildItem $_ | Select-Object FullName,Length,LastWriteTime }}
  }
}