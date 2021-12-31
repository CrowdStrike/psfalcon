function Get-FalconLibrary {
<#
.SYNOPSIS
List available Real-time Response Library scripts
.PARAMETER Platform
Operating system platform
.EXAMPLE
PS>Get-FalconScript -Platform windows

List scripts from the Windows library.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateSet('linux','mac','windows')]
        [string] $Platform
    )
    begin {
        $CurrentProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        
    }
    process {
        $Request = Invoke-WebRequest -Uri "https://github.com/bk-cs/rtr/tree/main/$Platform" -UseBasicParsing
        if ($Request.Links) {
            ($Request.Links | Where-Object { $_.title -match "\.(sh|ps1)" }).Title
        } else {
            Write-Error "Unable to retrieve script list for '$Platform'."
        }
    }
    end {
        $ProgressPreference = $CurrentProgress
    }
}
function Invoke-FalconLibrary {
<#
.SYNOPSIS
Execute a Real-time Response Library script
.DESCRIPTION
Requires 'real-time-response-admin:write'.
.PARAMETER Name
Script name
.PARAMETER Arguments
Arguments to include with 'runscript'
.PARAMETER Timeout
Length of time to wait for a result, in seconds
.PARAMETER QueueOffline
Add non-responsive Hosts to the offline queue
.PARAMETER HostId
Host identifier
.PARAMETER HostIds
Host identifier(s)
.EXAMPLE
PS>Invoke-FalconScript -Name list_sensor_tags -HostIds <id>, <id>

List the FalconSensorTag values for hosts <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = 'HostId')]
    param(
        [Parameter(ParameterSetName = 'HostId', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = 'HostId', Position = 2)]
        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostId')]
        [Parameter(ParameterSetName = 'HostIds')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostId', Mandatory = $true, ValueFromPipeline = $true)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $HostId,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds
    )
    begin {
        if ($PSBoundParameters.Timeout -and $PSBoundParameters.Arguments -notmatch '-Timeout=\d+') {
            $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
        }
    }
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'HostId') {
                $HostInfo = Get-FalconHost -Ids $PSBoundParameters.HostId |
                    Select-Object cid, device_id, platform_name
                if ($HostInfo.platform_name) {
                    $RawScript = Get-LibraryScript -Platform $HostInfo.platform_name -Name $PSBoundParameters.Name
                    if ($RawScript) {
                        $InvokeParam = @{
                            HostId    = $HostInfo.device_id
                            Command   = 'runscript'
                            Arguments = '-Raw=```' + $RawScript + '```'
                        }
                        if ($PSBoundParameters.Arguments) {
                            $InvokeParam.Arguments += " $($PSBoundParameters.Arguments)"
                        }
                        if ($PSBoundParameters.QueueOffline) {
                            $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                        }
                        foreach ($Result in (Invoke-FalconRtr @InvokeParam)) {
                            if ($Result.stdout) {
                                $Result.stdout = try {
                                    $Result.stdout -split '\n' | ForEach-Object {
                                        $_ | ConvertFrom-Json
                                    }
                                } catch {
                                    $Result.stdout
                                }
                            }
                            $Result
                        }
                    } else {
                        throw "No script matching '$($PSBoundParameters.Name)' for $($HostInfo.platform_name)."
                    }
                } else {
                    throw "No host found matching '$($PSBoundParameters.Id)'."
                }
            } else {
                $HostInfo = Get-FalconHost -Ids $PSBoundParameters.HostIds |
                    Select-Object cid, device_id, platform_name
                foreach ($Platform in ($HostInfo.platform_name | Group-Object).Name) {
                    $RawScript = Get-LibraryScript -Platform $Platform -Name $PSBoundParameters.Name
                    if ($RawScript) {
                        $InvokeParam = @{
                            Command   = 'runscript'
                            Arguments =  '-Raw=```' + $RawScript + '```'
                            HostIds   = ($HostInfo | Where-Object { $_.platform_name -eq $Platform }).device_id
                        }
                        if ($PSBoundParameters.Arguments) {
                            $InvokeParam.Arguments += " $($PSBoundParameters.Arguments)"
                        }
                        @('Timeout','QueueOffline').foreach{
                            if ($PSBoundParameters.Keys -contains $_) {
                                $InvokeParam[$_] = $PSBoundParameters.$_
                            }
                        }
                        foreach ($Result in (Invoke-FalconRtr @InvokeParam)) {
                            if ($Result.stdout) {
                                $Result.stdout = try {
                                    $Result.stdout -split '\n' | ForEach-Object {
                                        $_ | ConvertFrom-Json
                                    }
                                } catch {
                                    $Result.stdout
                                }
                            }
                            $Result
                        }
                    } else {
                        Write-Error "No script matching '$($PSBoundParameters.Name)' for $Platform."
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}