function Invoke-FalconRTR {
<#
.Synopsis
Start Real-time Response session(s) in groups of 500 hosts, execute a command and output the result
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
real-time-response:read
.Role
real-time-response:write
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
        [integer] $Timeout,

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
        # Set time values for command confirmation when interacting with a single host
        $ConfirmTime = 2
        $MaxConfirmTime = if ($PSBoundParameters.Timeout) {
            $PSBoundParameters.Timeout
        } else {
            30
        }
        if ($PSBoundParameters.Command -eq 'runscript' -and $PSBoundParameters.Timeout -and
        $PSBoundParameters.Arguments -notmatch "-Timeout=\d{2,3}") {
            # Force 'Timeout' into 'Arguments' when using 'runscript'
            $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
        }
        # Determine available Real-time Response commands and set permission level
        $ReadOnly = (Get-Command 'Invoke-FalconCommand').Parameters.GetEnumerator().Where({
            $_.Key -eq 'Command' }).Value.Attributes.ValidValues
        $Responder = (Get-Command 'Invoke-FalconResponderCommand').Parameters.GetEnumerator().Where({
            $_.Key -eq 'Command' }).Value.Attributes.ValidValues | Where-Object { $ReadOnly -notcontains $_ }
        $Admin = (Get-Command 'Invoke-FalconAdminCommand').Parameters.GetEnumerator().Where({
            $_.Key -eq 'Command' }).Value.Attributes.ValidValues | Where-Object { $ReadOnly -notcontains $_ -and
            $Responder -notcontains $_ }
        $Permission = switch ($PSBoundParameters.Command) {
            { $_ -eq 'runscript' -or $Admin -contains $_ } { 'Admin' }
            { $Responder -contains $_ }                    { 'Responder' }
            default                                        { $null }
        }
        # Set Real-time Response command using $Permission
        $InvokeCmd = if ($PSBoundParameters.Command -eq 'get' -and ($PSBoundParameters.HostIds |
        Measure-Object).Count -gt 1) {
            'Invoke-FalconBatchGet'
        } else {
            "Invoke-Falcon$($Permission)Command"
        }
        if (($PSBoundParameters.HostIds | Measure-Object).Count -eq 1) {
            # Set confirmation command to match $Permission when interacting with a single host
            $ConfirmCmd = "Confirm-Falcon$($Permission)Command"
        }
        function Write-Result ($Object) {
            $Object.PSObject.Properties | ForEach-Object {
                $Value = if (($_.Value -is [object[]]) -and ($_.Value[0] -is [string])) {
                    # Convert array results into strings
                    $_.Value -join ', '
                } elseif ($_.Value.code -and $_.Value.message) {
                    # Convert error code and message into string
                    "$($_.Value.code): $($_.Value.message)"
                } else {
                    $_.Value
                }
                $Name = if ($_.Name -eq 'task_id') {
                    # Rename 'task_id'
                    'cloud_request_id'
                } elseif ($_.Name -eq 'queued_command_offline') {
                    # Rename 'queued_command_offline'
                    'offline_queued'
                } else {
                    $_.Name
                }
                $Item = if ($Object.aid) {
                    # Match using 'aid' for batches
                    $Output | Where-Object { $_.aid -eq $Object.aid }
                } else {
                    # Assume single host
                    $Output[0]
                }
                if ($Item.PSObject.Properties.Name -contains $Name) {
                    # Add result to output
                    $Item.$Name = $Value
                }
            }
        }
    }
    process {
        for ($i = 0; $i -lt ($PSBoundParameters.HostIds | Measure-Object).Count; $i += 500) {
            try {
                [array] $Output = ($PSBoundParameters.HostIds[$i..($i + 499)]).foreach{
                    # Create base output object for each host
                    [PSCustomObject] @{
                        aid = $_
                        session_id = $null
                        cloud_request_id = $null
                        complete = $false
                        offline_queued = $false
                        stdout = $null
                        stderr = $null
                        errors = $null
                    }
                }
                # Determine total number of hosts and set request parameters
                $HostParam = if ($Output.aid.count -eq 1) {
                    'HostId'
                } else {
                    'HostIds'
                }
                $Param = @{ $HostParam = $Output.aid }
                switch ($PSBoundParameters.Keys) {
                    'QueueOffline' { $Param['QueueOffline'] = $PSBoundParameters.$_ }
                    'Timeout'      {
                        if ($HostParam -eq 'HostIds') {
                            $Param['Timeout'] = $PSBoundParameters.$_
                        }
                    }
                }
                # Start session and capture results
                $Init = Start-FalconSession @Param
                if ($Init) {
                    $Content = if ($Init.hosts) {
                        $Init.hosts
                    } else {
                        $Init
                    }
                    $Content | ForEach-Object {
                        Write-Result -Object $_
                    }
                    if ($Init.batch_id) {
                        $Output | Where-Object { $_.session_id } | ForEach-Object {
                            # Add batch_id
                            $_.PSObject.Properties.Add(
                                (New-Object PSNoteProperty('batch_id', $Init.batch_id)))
                        }
                    }
                    # Set command parameters based on init result
                    $SessionType = if ($HostParam -eq 'HostIds') {
                        'BatchId'
                        $IdValue = $Init.batch_id
                    } else {
                        'SessionId'
                        $IdValue = $Init.session_id
                    }
                    $Param = @{
                        $SessionType = $IdValue
                    }
                    switch ($PSBoundParameters.Keys) {
                        # Add user input to command parameters
                        'Command' {
                            if ($InvokeCmd -ne 'Invoke-FalconBatchGet') {
                                $Param[$_] = $PSBoundParameters.$_
                            }
                        }
                        'Arguments' {
                            if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                                $Param['FilePath'] = $PSBoundParameters.$_
                            } else {
                                $Param[$_] = $PSBoundParameters.$_
                            }
                        }
                        'Timeout' {
                            if ($SessionType -eq 'BatchId') {
                                $Param[$_] = $PSBoundParameters.$_
                            }
                        }
                    }
                    # Perform command request
                    $Request = & $InvokeCmd @Param
                }
                if ($Request -and $InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $Output | Where-Object { $_.session_id } | ForEach-Object {
                        # Add 'batch_get_cmd_req_id' for batch 'get' requests
                        $_.PSObject.Properties.Add((New-Object PSNoteProperty(
                            'batch_get_cmd_req_id', $Request.batch_get_cmd_req_id)))
                    }
                    # Capture results
                    $Request | ForEach-Object {
                        Write-Result -Object $_
                    }
                    $Output | ForEach-Object {
                        if ($_.stdout -eq 'C:\') {
                            # Remove 'stdout' from initial 'pwd' command to reduce confusion when using 'get'
                            $_.stdout = $null
                        }
                    }
                    # Output result
                    $Output
                } elseif ($Request -and $HostParam -eq 'HostIds') {
                    # Capture results and output
                    $Request | ForEach-Object {
                        Write-Result -Object $_
                    }
                    $Output
                } elseif ($Request) {
                    # Capture results
                    Write-Result -Object $Request
                    if ($Output.cloud_request_id -and $Output.complete -eq $false -and
                    $Output.offline_queued -eq $false) {
                        do {
                            # Loop command confirmation using intervals of $ConfirmTime
                            Start-Sleep -Seconds $ConfirmTime
                            $Confirm = & $ConfirmCmd -CloudRequestId $Output.cloud_request_id
                            Write-Result -Object $Confirm
                            $i += $ConfirmTime
                        } until (
                            # Break if command is complete or $MaxConfirmTime is reached
                            ($Output[0].complete -eq $true) -or ($i -ge $MaxConfirmTime)
                        )
                    }
                    # Output results
                    $Output
                }
            } catch {
                $_
            }
        }
    }
}