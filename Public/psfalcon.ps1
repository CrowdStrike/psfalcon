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