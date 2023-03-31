#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS

.PARAMETER

#>
<#
**NOTE**: Similar to the [other example](#upload-and-execute-a-local-script) this will run a script as a secondary
PowerShell process on the target device, which helps when scripts are expected to exceed the Real-time Response
timeout limit. The downside is that you will not be able to return results from the script unless you write them
to a local file on the target host that you access later.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=1)]
    [ValidateScript({ Test-Path $_ })]
    [string]$Path,
    [Parameter(Mandatory,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$HostId,
    [Parameter(Position=3)]
    [int]$Timeout
)
begin {
    $EncodedScript = [Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $Path -Raw)))
}
process {
    $Param = @{
        Command = 'runscript'
        Arguments = '-Raw=```Start-Process -FilePath powershell.exe -ArgumentList "-Enc ' + $EncodedScript + '"```'
        HostId = $HostId
    }
    if ($HostIds.count -gt 1 -and $Timeout) { $Param['Timeout'] = $Timeout }
    Invoke-FalconRtr @Param
}