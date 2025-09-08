#Requires -Version 5.1
#using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Transform a Firewall Activity export into objects that can used with ConvertTo-FalconFirewallRule
.DESCRIPTION
Renames and converts Firewall Activity Json export fields into those expected by ConvertTo-FalconFirewallRule,
then groups the converted objects by 'image_name', then 'direction' and 'protocol' to de-duplicate rules.

This script assumes all rules in the Firewall Activity export should be converted into 'ALLOW' rules. The final
conversion must be checked for errors and modified before final rule use.
.PARAMETER InputObject
Firewall Activity export objects, imported from Json
.EXAMPLE
$Rule = Get-Content .\firewall_activity.json | ConvertFrom-Json | .\create_rules_from_activity_json.ps1
New-FalconFirewallGroup -Name 'my_group' -Enabled $true -Platform windows -Rule $Rule
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,ValueFromPipeline,Position=1)]
  [PSCustomObject]$InputObject
)
begin {
  [System.Collections.Generic.List[PSCustomObject]]$Rule = @()
  [System.Collections.Generic.List[PSCustomObject]]$Output = @()
}
process {
  $InputObject | ForEach-Object {
    $Rule.Add(([PSCustomObject]@{
      direction = switch ($_.connection_direction) {
        # Convert [int32] to expected [string]
        1 { 'IN' }
        2 { 'OUT' }
      }
      address_family = ($_.ipv -replace 'v',$null).ToUpper()
      local_address = $_.local_address
      local_port = [int32]$_.local_port
      network_location = switch ($_.network_profile) {
        # Convert [int32] to expected [string]
        1 { 'DOMAIN' }
        2 { 'PUBLIC' }
        4 { 'PRIVATE' }
        default { 'ANY' }
      }
      platform_ids = switch ($_.platform) {
        # Convert [string] to expected [int32]
        'windows' { 0 }
        'mac' { 1 }
        'linux' { 3 }
      }
      protocol = $_.protocol
      remote_address = $_.remote_address
      remote_port = [int32]$_.remote_port
      image_name = ($_.image_file_name -replace '^\\Device\\HarddiskVolume\d{1,2}\\','**\').Trim()
    }))
  }
}
end {
  foreach ($ImageName in ($Rule | Group-Object -Property image_name)) {
    # Group rules with 'image_name', then 'direction' and 'protocol'
    foreach ($DirProt in ($ImageName.Group | Group-Object -Property direction,protocol)) {
      [string[]]$Arr = $DirProt.Name -split ', ',2
      [string[]]$IpFamily = ($DirProt.Group | Group-Object -Property address_family).Name
      $Obj = @{
        name = (($ImageName.Name | Split-Path -Leaf) -replace '\.\w{1,3}$',
          $null -replace '[^a-zA-Z0-9\. ]','').Trim()
        action = 'ALLOW'
        direction = $Arr[0]
        enabled = $true
        address_family = if (($IpFamily | Measure-Object).Count -gt 1) { 'BOTH' } else { $IpFamily }
        protocol = $Arr[1]
        image_name = $ImageName.Name
      }
      @('network_location','platform_ids','description').foreach{
        $Obj[$_] = if ($_ -eq 'description') {
          # Add multiple command_line values as 'description'
          ($DirProt.Group | Group-Object -Property $_).Name -join "`r`n"
        } else {
          ($DirProt.Group | Group-Object -Property $_).Name
        }
      }
      @('local_address','local_port','remote_address','remote_port').foreach{
          $Value = ($DirProt.Group | Group-Object -Property $_).Name
        if (($Value | Measure-Object).Count -le 5) {
          # Add when 5 or less values are present
          $Obj[$_] = $Value -join ','
        } elseif ($_ -match '(local|remote)_address') {
          # Add as 'ANY' when more than 5 values are present
          $Obj[$_] = '*'
        }
      }
      $Output.Add([PSCustomObject]$Obj)
    }
  }
  $Output | ConvertTo-FalconFirewallRule
}