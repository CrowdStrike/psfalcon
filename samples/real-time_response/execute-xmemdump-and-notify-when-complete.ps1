#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Using Real-time Response, run a complete xmemdump on a host and notify when complete
.PARAMETER HostId
Host identifier
.PARAMETER Path
Full path for 'xmemdump Complete' output
#>
param(
    [Parameter(Mandatory,Position=1)]
    [string]$HostId,
    [Parameter(Mandatory,Position=2)]
    [string]$Path
)
$Verbose = $VerbosePreference
$VerbosePreference = 'Continue'
$Script = @'
$File = New-Object System.IO.FileInfo {0}
try {
    $Stream = $File.Open([System.IO.FileMode]::Open,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None)
    if ($Stream) { $Stream.Close() }
    $false
} catch {
    $true
}
'@
$Script = $Script -replace '\{0\}',$Path
$Argument = '-Raw=```' + $Script + '```'
try {
    $Dump = Invoke-FalconRtr -Command xmemdump -Argument "Complete $Path" -HostId $HostId
    if ($Dump) {
        $Status = Invoke-FalconRtr -Command runscript -Argument $Argument -HostId $HostId
        do {
            Start-Sleep -Seconds 30
            $Status = Invoke-FalconRtr -Command runscript -Argument $Argument -HostId $HostId
        } while ($Status -and $Status.stdout -eq 'True')
        Write-Output "'xmemdump' is complete on host '$HostId'. [$Path]"
    }
} catch {
    throw $_
} finally {
    $VerbosePreference = $Verbose
}
