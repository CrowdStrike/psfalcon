#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Generate a CSV of minimum supported sensor version by Linux kernel and distro_version
.PARAMETER Path
Path to a text file containing a list of kernels to compare
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=1)]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            $true
        } else {
            throw "Cannot find path '$_' because it does not exist or is not a file."
        }
    })]
    [string]$Path
)
begin {
    [string]$Path = if (![IO.Path]::IsPathRooted($PSBoundParameters.Path)) {
        $FullPath = Join-Path -Path (Get-Location).Path -ChildPath $PSBoundParameters.Path
        $FullPath = Join-Path -Path $FullPath -ChildPath '.'
        [IO.Path]::GetFullPath($FullPath)
    } else {
        $PSBoundParameters.Path
    }
    [string]$OutputFile = Join-Path (Get-Location).Path "KernelSupport_$(Get-Date -Format FileDateTime).csv"
}
process {
    try {
        # Gather list of kernels from text file
        [string[]]$Kernel = Get-Content $Path | Where-Object { ![string]::IsNullOrEmpty($_) }
        if ($Kernel) {
            # Retrieve entire list of supported kernels
            [object[]]$Request = Get-FalconKernel -Limit 500 -All
            if ($Request) {
                # Filter to supported kernels
                [object[]]$Content = $Request | Where-Object { $Kernel -contains $_.release } |
                    Select-Object release,architecture,distro,distro_version,
                    base_package_supported_sensor_versions,ztl_supported_sensor_versions,
                    ztl_module_supported_sensor_versions
                if ($Content) {
                    [System.Collections.Generic.List[object]]$Output = @($Content).foreach{
                        # Create 'minimum_sensor_version' property, using lowest listed version
                        [string]$Minimum = ($_ | Select-Object base_package_supported_sensor_versions,
                        ztl_supported_sensor_versions,ztl_module_supported_sensor_versions
                        ).PSObject.Properties.Value | Group-Object | Sort-Object Name |
                            Select-Object -ExpandProperty Name -First 1
                        [string]$Value = if ($Minimum) { $Minimum } else { 'UNKNOWN' }
                        $_.PSObject.Properties.Add((New-Object PSNoteProperty(
                            'minimum_supported_sensor_version',$Value)))
                        [void]$_.PSObject.Properties.Remove('base_package_supported_sensor_versions')
                        [void]$_.PSObject.Properties.Remove('ztl_supported_sensor_versions')
                        [void]$_.PSObject.Properties.Remove('ztl_module_supported_sensor_versions')
                        $_ | Select-Object release,architecture,distro,distro_version,
                            minimum_supported_sensor_version
                    }
                    @($Kernel).foreach{
                        if ($Output.release -notcontains $_) {
                            $Output.Add([PSCustomObject]@{
                                release = $_
                                architecture = $null
                                distro = $null
                                distro_version = $null
                                minimum_supported_sensor_version = 'NO_MATCH'
                            })
                        }
                    }
                    if (!$Output) { throw 'No results.' }
                    $Output | Export-Csv -Path $OutputFile -NoTypeInformation -Append
                }
            }
        }
    } catch {
        throw $_
    }
}
end { if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }}