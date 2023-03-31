#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Download the installer package assigned to your default Windows Sensor Update policy
.PARAMETER Path
Output directory
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=1)]
    [ValidateScript({
        if (Test-Path -Path $_ -PathType Container) {
            $true
        } else {
            throw "Cannot find path '$_' because it does not exist or is not a directory."
        }
    })]
    [string]$Path
)
begin {
    # Ensure absolute path for output directory
    $OutputDirectory = if (![IO.Path]::IsPathRooted($PSBoundParameters.Path)) {
        $FullPath = Join-Path -Path (Get-Location).Path -ChildPath $PSBoundParameters.Path
        $FullPath = Join-Path -Path $FullPath -ChildPath '.'
        [IO.Path]::GetFullPath($FullPath)
    } else {
        $PSBoundParameters.Path
    }
}
process {
    try {
        # Retrieve Sensor Update policy detail
        $Policy = Get-FalconSensorUpdatePolicy -Filter "platform_name:'Windows'+name:'platform_default'" -Detailed
        if ($Policy.platform_name -and $Policy.settings) {
            # Use build and sensor_version to create regex pattern
            [regex]$Pattern = "^($([regex]::Escape(
                ($Policy.settings.sensor_version -replace '\.\d+$',$null)))\.\d{1,}|\d\.\d{1,}\.$(
                $Policy.settings.build.Split('|')[0]))$"
            $Match = try {
                # Select matching installer from list for 'platform_name' using regex pattern
                Get-FalconInstaller -Filter "platform:'$($Policy.platform_name.ToLower())'" -Detailed |
                    Where-Object { $_.version -match $Pattern -and $_.description -match 'Falcon Sensor' }
            } catch {
                throw 'Unable to find installer through version match'
            }
            if ($Match.sha256 -and $Match.name) {
                $Installer = Join-Path -Path $OutputDirectory -ChildPath $Match.name
                if ((Test-Path $Installer) -and ((Get-FileHash -Algorithm SHA256 -Path $Installer) -eq
                $Match.sha256)) {
                    # Abort if matching file already exists
                    throw "File exists with matching hash [$($Match.sha256)]"
                } elseif (Test-Path $Installer) {
                    # Remove other versions
                    Remove-Item -Path $Installer -Force
                }
                # Download the installer package
                $Receive = Receive-FalconInstaller -Id $Match.sha256 -Path $Installer
                if (Test-Path $Receive.FullName) {
                    $Match | ForEach-Object {
                        # Output installer information with 'file_path' of local file
                        $_.PSObject.Properties.Add((New-Object PSNoteProperty('file_path',$Receive.FullName)))
                        $_
                    }
                } else {
                    throw "Installer download failed. [$($Match.sha256)]"
                }
            } else {
                throw "Properties 'sha256' or 'name' missing from installer result."
            }
        } else {
            throw "Unable to retrieve default policy for Windows."
        }
    } catch {
        throw $_
    }
}