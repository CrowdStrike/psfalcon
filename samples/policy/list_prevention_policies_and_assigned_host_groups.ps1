#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Create a CSV containing a list of Prevention policies, their assigned Host Groups, and total member counts for
all CIDs within a Flight Control environment
.DESCRIPTION
A CSV will be created in the local directory containing the script results
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
.\list_prevention_policies_and_assigned_host_groups.ps1 -ClientId abc -ClientSecret def -Cloud us-1
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
      [object[]]$MemberCid = Get-FalconMemberCid -Detailed -All | Where-Object { $_.status -eq 'active' } |
        Select-Object name,child_cid
      [void](Revoke-FalconToken)
    }
  }
  [string]$OutputFile = Join-Path (Get-Location).Path "policies_and_host_groups_$(
    Get-Date -Format FileDateTime).csv"
}
process {
  if (!$MemberCid) { throw "Child CIDs undefined. Unable to continue." }
  foreach ($Cid in $MemberCid) {
    try {
      # Request an authorization token from the Falcon APIs for each member CID
      Request-FalconToken @Token -MemberCid $Cid.child_cid
      if ((Test-FalconToken).Token -eq $true) {
        Write-Host "Authorized with '$($Cid.name)'. Collecting policies..."
        try {
          Get-FalconPreventionPolicy -Detailed -All | Select-Object @{l='cid';e={$Cid.child_cid}},@{l='cid_name';
            e={$Cid.name}}@{l='type';e={'prevention_policy'}},id,platform_name,name,enabled,
            @{l='assigned_groups';e={$_.groups.id -join ','}},@{l='total_members';e={
            Get-FalconPreventionPolicyMember -Id $_.id -Total}} | Export-Csv $OutputFile -NoTypeInformation -Append
        } catch {
          Write-Error "Failed to collect prevention policies from '$($Cid.name)'."
        }
        try {
          Get-FalconHostGroup -Detailed -All | Select-Object @{l='cid';e={$Cid.child_cid}},@{l='cid_name';
            e={$Cid.name}},@{l='type';e={'host_group',$_.group_type -join ':'}},id,@{l='platform_name';e={''}},
            name,@{l='enabled';e={''}},@{l='assigned_groups';e={''}},@{l='total_members';e={
            Get-FalconHostGroupMember -Id $_.id -Total}} | Export-Csv $OutputFile -NoTypeInformation -Append
        } catch {
          Write-Error "Failed to collect host groups from '$($Cid.name)'."
        }
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
end { if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }}