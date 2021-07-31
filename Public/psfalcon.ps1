function Get-FalconQueue {
<#
.Synopsis
Create a Real-time Response offline queue report
.Parameter Days
Days worth of results to retrieve [default: 7]
.Role
real-time-response-admin:write
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [int] $Days
    )
    begin {
        function Get-CommandArray ([string] $Permission) {
            # Retrieve 'ValidValues' for 'Command' parameter
            (Get-Command "Invoke-Falcon$($Permission)Command").Parameters.GetEnumerator().Where({
                $_.Key -eq 'Command' }).Value.Attributes.ValidValues
        }
        # Retrieve available Real-time Response command lists, by permission level
        @($null, 'Responder', 'Admin').foreach{
            $Name = if ($_ -eq $null) {
                'ReadOnly'
            } else {
                $_
            }
            $Value = switch ($Name) {
                'ReadOnly'  { Get-CommandArray -Permission $null }
                'Responder' { Get-CommandArray -Permission $_ | Where-Object { $ReadOnly -notcontains $_ } }
                'Admin'     { Get-CommandArray -Permission $_ | Where-Object { $ReadOnly -notcontains $_ -and
                    $Responder -notcontains $_ }
                }
            }
            New-Variable -Name $Name -Value $Value
        }
        function Add-Field ($Object, $Name, $Value) {
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        $Days = if ($PSBoundParameters.Days) {
            $PSBoundParameters.Days
        } else {
            7
        }
        $OutputFile = Join-Path -Path ([Environment]::CurrentDirectory) -ChildPath "FalconQueue_$(
            Get-Date -Format FileDateTime).csv"
        $Filter = "(deleted_at:null+commands_queued:1),(created_at:>'last $Days days'+commands_queued:1)"
    }
    process {
        try {
            Get-FalconSession -Filter $Filter -All -Verbose | ForEach-Object {
                Get-FalconSession -Ids $_ -Queue -Verbose | ForEach-Object {
                    foreach ($Session in $_) {
                        $Session.Commands | ForEach-Object {
                            $Object = [PSCustomObject] @{
                                aid                = $Session.aid
                                user_id            = $Session.user_id
                                user_uuid          = $Session.user_uuid
                                session_id         = $Session.id
                                session_created_at = $Session.created_at
                                session_deleted_at = $Session.deleted_at
                                session_updated_at = $Session.updated_at
                                session_status     = $Session.status
                                command_complete   = $false
                                command_stdout     = $null
                                command_stderr     = $null
                            }
                            $_.PSObject.Properties | ForEach-Object {
                                $Name = if ($_.Name -match '^(created_at|deleted_at|status|updated_at)$') {
                                    "command_$($_.Name)"
                                } else {
                                    $_.Name
                                }
                                Add-Field -Object $Object -Name $Name -Value $_.Value
                            }
                            if ($Object.command_status -eq 'FINISHED') {
                                $Permission = if ($Admin -contains $Object.base_command) {
                                    'Admin'
                                } elseif ($Responder -contains $Object.base_command) {
                                    'Responder'
                                } else {
                                    $null
                                }
                                $Param = @{
                                    CloudRequestId = $Object.cloud_request_id
                                    Verbose        = $true
                                    ErrorAction    = 'SilentlyContinue'
                                }
                                $CmdResult = & "Confirm-Falcon$($Permission)Command" @Param
                                if ($CmdResult) {
                                    ($CmdResult | Select-Object stdout, stderr, complete).PSObject.Properties |
                                    ForEach-Object {
                                        $Object."command_$($_.Name)" = $_.Value
                                    }
                                }
                            }
                            $Object | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                        }
                    }
                }
            }
        } catch {
            throw $_
        } finally {
            if (Test-Path $OutputFile) {
                Get-ChildItem $OutputFile | Out-Host
            }
        }
    }
}
function Invoke-FalconRTR {
<#
.Synopsis
Start Real-time Response session(s), execute a command and output the result(s)
.Parameter Command
Real-time Response command
.Parameter Arguments
Arguments to include with the command
.Parameter HostIds
Host identifier(s) to target
.Parameter GroupId
Host Group identifier containing hosts to target
.Parameter Timeout
Length of time to wait for a result, in seconds
.Parameter QueueOffline
Add non-responsive Hosts to the offline queue
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = 'HostIds')]
    param(
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true, Position = 1)]
        [ValidateSet('cat', 'cd', 'clear', 'cp', 'csrutil', 'encrypt', 'env', 'eventlog', 'filehash', 'get',
            'getsid', 'history', 'ifconfig', 'ipconfig', 'kill', 'ls', 'map', 'memdump', 'mkdir', 'mount', 'mv',
            'netstat', 'ps', 'put', 'reg delete', 'reg load', 'reg query', 'reg set', 'reg unload', 'restart',
            'rm', 'run', 'runscript', 'shutdown', 'umount', 'unmap', 'update history', 'update install',
            'update list', 'users', 'xmemdump', 'zip')]
        [string] $Command,

        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [Parameter(ParameterSetName = 'GroupId', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [Parameter(ParameterSetName = 'GroupId', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostIds')]
        [Parameter(ParameterSetName = 'GroupId')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds,

        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        function Get-CommandArray ([string] $Permission) {
            # Retrieve 'ValidValues' for 'Command' parameter
            (Get-Command "Invoke-Falcon$($Permission)Command").Parameters.GetEnumerator().Where({
                $_.Key -eq 'Command' }).Value.Attributes.ValidValues
        }
        function Initialize-Output ([array] $HostIds) {
            # Create initial array of output for each host
            ($HostIds).foreach{
                $Item = [PSCustomObject] @{
                    aid              = $_
                    batch_id         = $null
                    session_id       = $null
                    cloud_request_id = $null
                    complete         = $false
                    offline_queued   = $false
                    errors           = $null
                    stderr           = $null
                    stdout           = $null
                }
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id', $null)))
                }
                $Item
            }
        }
        function Get-Result ($Object) {
            foreach ($Item in $Object) {
                # Update output with result data
                ($Item | Select-Object $RtrFields).PSObject.Properties | Where-Object { $_.Value } |
                ForEach-Object {
                    $Field = if ($_.Name -eq 'task_id') {
                        # Rename 'task_id' to 'cloud_request_id'
                        'cloud_request_id'
                    } else {
                        $_.Name
                    }
                    $Value = if (($_.Value -is [object[]]) -and ($_.Value[0] -is [string])) {
                        # Convert array result into string
                        $_.Value -join ', '
                    } elseif ($_.Value.code -and $_.Value.message) {
                        # Convert error code and message into string
                        (($_.Value).foreach{
                            "$($_.code): $($_.message)"
                        }) -join ', '
                    } else {
                        $_.Value
                    }
                    $Output | Where-Object { $_.aid -eq $Item.aid } | ForEach-Object {
                        $_.$Field = $Value
                    }
                }
            }
        }
        if ($PSBoundParameters.Timeout -and $PSBoundParameters.Command -eq 'runscript' -and
        $PSBoundParameters.Arguments -notmatch '-Timeout=\d{2,3}') {
            # Force 'Timeout' into 'Arguments' when using 'runscript'
            $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
        }
        # Retrieve available Real-time Response command lists, by permission level
        @($null, 'Responder', 'Admin').foreach{
            $Name = if ($_ -eq $null) {
                'ReadOnly'
            } else {
                $_
            }
            $Value = switch ($Name) {
                'ReadOnly'  { Get-CommandArray -Permission $null }
                'Responder' { Get-CommandArray -Permission $_ | Where-Object { $ReadOnly -notcontains $_ } }
                'Admin'     { Get-CommandArray -Permission $_ | Where-Object { $ReadOnly -notcontains $_ -and
                    $Responder -notcontains $_ }
                }
            }
            New-Variable -Name $Name -Value $Value
        }
        # Set Real-time Response command using $Permission
        $InvokeCmd = if ($PSBoundParameters.Command -eq 'get') {
            'Invoke-FalconBatchGet'
        } else {
            $Permission = if ($PSBoundParameters.Command -eq 'runscript') {
                # Force 'Admin' for 'runscript'
                'Admin'
            } else {
                switch ($PSBoundParameters.Command) {
                    { $Admin -contains $_ }     { 'Admin' }
                    { $Responder -contains $_ } { 'Responder' }
                    default                     { $null }
                }
            }
            "Invoke-Falcon$($Permission)Command"
        }
        # Real-time Response fields to capture from results
        $RtrFields = @('aid', 'complete', 'errors', 'offline_queued', 'session_id', 'stderr', 'stdout', 'task_id')
    }
    process {
        $HostArray = if ($PSBoundParameters.GroupId) {
            try {
                # Find Host Group member identifiers
                Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId
            } catch {
                throw $_
            }
        } else {
            # Use provided Host identifiers
            $PSBoundParameters.HostIds
        }
        try {
            for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 500) {
                # Create baseline output and define request parameters
                [array] $Output = Initialize-Output $HostArray[$i..($i + 499)]
                $InitParam = @{
                    HostIds = $Output.aid
                }
                if ($PSBoundParameters.QueueOffline) {
                    $InitParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                }
                # Define command request parameters
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $CmdParam = @{
                        FilePath = $PSBoundParameters.Arguments
                    }
                } else {
                    $CmdParam = @{
                        Command = $PSBoundParameters.Command
                    }
                    if ($PSBoundParameters.Arguments) {
                        $CmdParam['Arguments'] = $PSBoundParameters.Arguments
                    }
                }
                if ($PSBoundParameters.Timeout) {
                    @($InitParam, $CmdParam).foreach{
                        $_['Timeout'] = $PSBoundParameters.Timeout
                    }
                }
                # Request session
                $InitRequest = Start-FalconSession @InitParam
                Get-Result -Object $InitRequest.hosts
                if ($InitRequest.batch_id) {
                    $Output | Where-Object { $_.session_id } | ForEach-Object {
                        # Add batch_id to initialized sessions
                        $_.batch_id = $InitRequest.batch_id
                    }
                    # Perform command request
                    $CmdRequest = & $InvokeCmd @CmdParam -BatchId $InitRequest.batch_id
                    Get-Result -Object $CmdRequest
                    if ($InvokeCmd -eq 'Invoke-FalconBatchGet' -and $CmdRequest.batch_get_cmd_req_id) {
                        $Output | Where-Object { $_.session_id -and $_.complete -eq $true } | ForEach-Object {
                            # Add 'batch_get_cmd_req_id' and remove 'stdout' from session
                            $_.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id',
                                $CmdRequest.batch_get_cmd_req_id)))
                            $_.stdout = $null
                        }
                    }
                }
                $Output
            }
        } catch {
            throw $_
        }
    }
}
function Show-FalconModule {
<#
.Synopsis
Output information about your PSFalcon installation
#>
    [CmdletBinding()]
    param()
    begin {
        $Parent = Split-Path -Path $Script:Falcon.Api.Path($PSScriptRoot) -Parent
    }
    process {
        if (Test-Path "$Parent\PSFalcon.psd1") {
            $Module = Import-PowerShellDataFile $Parent\PSFalcon.psd1
            [PSCustomObject] @{
                ModuleVersion    = "v$($Module.ModuleVersion) {$($Module.GUID)}"
                ModulePath       = $Parent
                UserHome         = $HOME
                UserPSModulePath = ($env:PSModulePath -split ';') -join ', '
                UserSystem       = ("PowerShell $($PSVersionTable.PSEdition): v$($PSVersionTable.PSVersion)" +
                    " [$($PSVersionTable.OS)]")
            }
        } else {
            throw "Cannot find 'PSFalcon.psd1'"
        }
    }
}