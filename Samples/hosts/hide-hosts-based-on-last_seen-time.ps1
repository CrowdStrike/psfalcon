#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
param(
    [Parameter(Mandatory)]
    [ValidateRange(1,44)]
    [int]$Days
)
$Filter = ('last_seen:<{0}' -f "'now-$($Days)d'")
Get-FalconHost -Filter $Filter -All -OutVariable HostList | Invoke-FalconHostAction -Name hide_host
if (!$HostList) { "No hosts found using filter `"$Filter`"." }