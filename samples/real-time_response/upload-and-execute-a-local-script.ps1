#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Encode a local PowerShell script, then upload and run it on target hosts using Real-time Response
.PARAMETER Path
Path to PowerShell script to encode and transmit
.PARAMETER HostId
One or more host identifiers
.PARAMETER Argument
Arguments to include with the script
.NOTES
You will receive no output from the execution of the encoded script unless you design the script to output results
on the local host (or send them to another location) and check for them later.
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
    [string]$Argument
)
begin {
    $EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(
        (Get-Content -Path $Path -Raw)))
}
process {
    $Param = @{
        Command = 'runscript'
        Argument = '-Raw=```powershell.exe -Enc ' + $EncodedScript + '```'
        HostId = $HostId
    }
    if ($Argument) { $Param.Argument = $Param.Argument,' -CommandLine=```',$Argument,'```' -join $null }
    Invoke-FalconRtr @Param
}