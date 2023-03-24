#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
**NOTE**: This will get the content of a script from the local administrator computer, encode it (to minimize
potential errors due to quotation marks) and run it as a "Raw" script using `Invoke-FalconRtr`.
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
        Arguments = '-Raw=```powershell.exe -Enc ' + $EncodedScript + '```'
        HostId = $HostId
    }
    if ($HostId.count -gt 1 -and $Timeout) { $Param['Timeout'] = $Timeout }
    Invoke-FalconRtr @Param
}