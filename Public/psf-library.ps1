function Get-FalconLibrary {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateSet('linux','mac','windows')]
        [string] $Platform
    )
    begin {
        $CurrentProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        $Platform = $PSBoundParameters.Platform.ToLower()
    }
    process {
        $Request = Invoke-WebRequest -Uri "https://github.com/bk-cs/rtr/tree/main/$(
            $PSBoundParameters.Platform.ToLower())" -UseBasicParsing
        if ($Request.Links) {
            ($Request.Links | Where-Object { $_.title -match "\.(sh|ps1)" }).Title
        } else {
            Write-Error "Unable to retrieve script list for '$($PSBoundParameters.Platform.ToLower())'."
        }
    }
    end {
        $ProgressPreference = $CurrentProgress
    }
}
function Invoke-FalconLibrary {
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
        $PSBoundParameters.Name = $PSBoundParameters.Name.ToLower()
    }
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'HostId') {
                $HostInfo = Get-FalconHost -Ids $PSBoundParameters.HostId |
                    Select-Object cid, device_id, platform_name
                if (-not $HostInfo) {
                    throw "No host found matching '$($PSBoundParameters.HostId)'."
                }
                if ($HostInfo.platform_name) {
                    $Script = @{
                        Platform = $HostInfo.platform_name.ToLower()
                        Name     = $PSBoundParameters.Name
                    }
                    $RawScript = Get-LibraryScript @Script
                    if (-not $RawScript) {
                        throw "No script matching '$($Script.Name)' for '$($Script.Platform)'."
                    }
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
                                @($Result.stdout -split '\n').foreach{
                                    if (-not [string]::IsNullOrEmpty($_)) {
                                        $_ | ConvertFrom-Json
                                    }
                                }
                            } catch {
                                $Result.stdout
                            }
                        }
                        $Result
                    }
                } else {
                    throw "No host found matching '$($PSBoundParameters.HostId)'."
                }
            } else {
                $HostInfo = Get-FalconHost -Ids $PSBoundParameters.HostIds |
                    Select-Object cid, device_id, platform_name
                if (-not $HostInfo) {
                    throw "No hosts found matching $(
                        (@($PSBoundParameters.HostIds).foreach{ "'$_'" }) -join ', ')."
                }
                foreach ($Platform in ($HostInfo.platform_name | Group-Object).Name.ToLower()) {
                    $Script = @{
                        Platform = $Platform
                        Name     = $PSBoundParameters.Name
                    }
                    $RawScript = Get-LibraryScript @Script
                    if ($RawScript) {
                        $InvokeParam = @{
                            Command   = 'runscript'
                            Arguments = '-Raw=```' + $RawScript + '```'
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
                                    @($Result.stdout -split '\n').foreach{
                                        if (-not [string]::IsNullOrEmpty($_)) {
                                            $_ | ConvertFrom-Json
                                        }
                                    }
                                } catch {
                                    $Result.stdout
                                }
                            }
                            $Result
                        }
                    } else {
                        Write-Error "No script matching '$($Script.Name)' for '$($Script.Platform)'."
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}