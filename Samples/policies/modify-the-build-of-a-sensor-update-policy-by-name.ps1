#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
param(
    [Parameter(Mandatory,Position=1)]
    [string]$Name,
    [Parameter(Mandatory,Position=2)]
    [string]$Version
)
[string]$Id = Get-FalconSensorUpdatePolicy -Filter "name.raw:'$Name'"
if (!$Id) { throw "No policy found matching '$Name'." }
if ($Version -match '\.') { $Version = [string]($Version -split '\.')[-1] }
if ((Get-FalconBuild).build -notcontains $Version) { throw "'$Version' is not a valid build number." }
Edit-FalconSensorUpdatePolicy -Id $Id -Setting @{ build = $Version } | Select-Object id,name,@{Label='build';
    Expression={$_.settings.build}}