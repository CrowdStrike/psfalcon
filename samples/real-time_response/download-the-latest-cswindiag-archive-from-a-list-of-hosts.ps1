#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS

.PARAMETER

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$HostId
)
begin {
    # Script to check for latest 'cswindiag' archive
    [string]$CheckDiag = 'Get-ChildItem -Path (Join-Path $env:ProgramFiles "CrowdStrike\Rtr\PutRun") -Filter "CS' +
        'WinDiag*.zip" | Select-Object -First 1 -ExpandProperty FullName'
}
process {
    try {
        # Filter to Windows hosts
        [string[]]$HostList = $HostId | Select-Object -Unique | Get-FalconHost | Where-Object {
            $_.platform_name -eq 'Windows' } | Select-Object -ExpandProperty device_id
        if ($HostId -and !$HostList) { throw "'CsWinDiag' is only available for Windows hosts." }
        [string]$Argument = '-Raw=```' + $CheckDiag + '```'
        $GetList = $HostList | Invoke-FalconRtr -Command runscript -Argument $Argument | ForEach-Object {
            if ($_.stdout) {
                # If CsWinDiag present, issue 'get' command
                Write-Host "Issuing 'get' for '$($_.stdout | Split-Path -Leaf)' on host '$($_.aid)'..."
                Invoke-FalconRtr -Command get -Argument "'$($_.stdout)'" -HostId $_.aid
            } else {
                Write-Warning "No 'cswindiag' package found for host '$($_.aid)'."
            }
        }
        if ($GetList) {
            @($GetList).foreach{
                $_ | Confirm-FalconGetFile | ForEach-Object {
                    if ($_.sha256) {
                        # If download complete, and file does not exist, download file
                        [string]$File = Join-Path (Get-Location).Path "$($_.name | Split-Path -Leaf).7z"
                        if ((Test-Path $File) -eq $false) {
                            Write-Host "Downloading '$($_.name | Split-Path -Leaf)' from host '$($_.aid)'..."
                            $_ | Receive-FalconGetFile -Path $File
                        }
                    } else {
                        Write-Warning "'get' incomplete for host '$($_.aid)'."
                    }
                }
            }
        }
    } catch {
        throw $_
    }
}