#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
param(
    [Parameter(Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$GroupId
)
Get-FalconSvExclusion -Detailed -All | ForEach-Object {
    Edit-FalconSvExclusion -Id $_.id -GroupId @($_.groups.id,$GroupId)
}