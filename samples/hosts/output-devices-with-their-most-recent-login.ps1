#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Output device(s) and their most recently logged-in user
.PARAMETER String
The hostname of a specific device to output
#>
param([string]$String)
[string[]]$Select = 'cid','device_id','platform_name','hostname','machine_domain','login_history'
$Param = @{ Include = 'login_history'; Detailed = $true }
if ($String) { $Param['Filter'] = "hostname:['$String']" } else { $Param['All'] = $true }
[object[]]$HostList = Get-FalconHost @Param | Select-Object $Select
if (!$HostList) { throw "No host(s) found." }
foreach ($i in $HostList) {
  $Recent = if ($i.platform_name -eq 'Windows') {
    [string[]]$Ignore = 'Font Driver Host','Window Manager','NT AUTHORITY'
    $i.login_history | Where-Object { $Ignore -notcontains ($_.user_name -split '\\')[0] } |
      Select-Object -First 1
  } else {
    $i.login_history | Select-Object -First 1
  }
  [void]($i.PSObject.Properties.Remove('login_history'))
  $i.PSObject.Properties.Add((New-Object PSNoteProperty('last_login_user',$Recent.user_name)))
  $i.PSObject.Properties.Add((New-Object PSNoteProperty('last_login_time',$Recent.login_time)))
  $i
}