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
                    base_command     = $null
                    query_time       = $null
                    complete         = $false
                    stdout           = $null
                    stderr           = $null
                    errors           = $null
                    offline_queued   = $false
                }
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id', $null)))
                }
                $Item
            }
        }
        function Get-Result ($Object) {
            $Content = if ($Object.hosts) {
                $Object.hosts
            } else {
                $Object
            }
            foreach ($Item in $Content) {
                $Item.PSObject.Properties | ForEach-Object {
                    $Name = if ($_.Name -eq 'task_id') {
                        # Rename 'task_id'
                        'cloud_request_id'
                    } elseif ($_.Name -eq 'queued_command_offline') {
                        # Rename 'queued_command_offline'
                        'offline_queued'
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
                    # Add result to output
                    $Output | Where-Object { $_.aid -eq $Item.aid } | ForEach-Object {
                        $_.$Name = $Value
                    }
                }
            }
        }
        # Force 'Timeout' into 'Arguments' when using 'runscript'
        if ($PSBoundParameters.Command -eq 'runscript' -and $PSBoundParameters.Timeout -and
        $PSBoundParameters.Arguments -notmatch '-Timeout=\d{2,3}') {
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
                'Admin'     {
                    Get-CommandArray -Permission $_ | Where-Object {
                        $ReadOnly -notcontains $_ -and $Responder -notcontains $_ }
                }
            }
            New-Variable -Name $Name -Value $Value
        }
        # Set Real-time Response command using $Permission
        $InvokeCmd = if ($PSBoundParameters.Command -eq 'get') {
            'Invoke-FalconBatchGet'
        } else {
            $Permission = switch ($PSBoundParameters.Command) {
                { $_ -eq 'runscript' -or $Admin -contains $_ } { 'Admin' }
                { $Responder -contains $_ }                    { 'Responder' }
                default                                        { $null }
            }
            "Invoke-Falcon$($Permission)Command"
        }
        $HostArray = if ($PSCmdlet.ParameterSetName -eq 'GroupId') {
            try {
                # Verify group has less than 10,000 members and retrieve results
                if ((Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -Total) -lt 10000) {
                    Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -All
                } else {
                    Write-Error "Number of group members exceeds API limit of 10,000 results."
                }
            } catch {
                throw $_
            }
        } else {
            # Use $HostIds
            $PSBoundParameters.HostIds
        }
    }
    process {
        for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 500) {
            # Create baseline output and individual request parameters
            [array] $Output = Initialize-Output $HostArray[$i..($i + 499)]
            $InitParam = @{
                HostIds = $Output.aid
            }
            $CmdParam = @{}
            switch ($PSBoundParameters.Keys) {
                'Arguments' {
                    if ($_ -eq 'get') {
                        $CmdParam['FilePath'] = $PSBoundParameters.$_
                    } else {
                        $CmdParam[$_] = $PSBoundParameters.$_
                    }
                }
                'Command' {
                    if ($_ -ne 'get') {
                        $CmdParam[$_] = $PSBoundParameters.$_
                    }
                }
                'Timeout' {
                    $InitParam[$_] = $PSBoundParameters.$_
                    $CmdParam[$_] = $PSBoundParameters.$_
                }
                'QueueOffline' {
                    $InitParam[$_] = $PSBoundParameters.$_
                }
            }
            try {
                # Request session and capture result
                $InitRequest = Start-FalconSession @InitParam
                Get-Result $InitRequest
                if ($InitRequest.batch_id) {
                    $Output | Where-Object { $_.session_id } | ForEach-Object {
                        # Add batch_id to initialized sessions
                        $_.batch_id = $InitRequest.batch_id
                    }
                    # Perform command request and capture result
                    Get-Result (& $InvokeCmd @CmdParam -BatchId $InitRequest.batch_id)
                }
            } catch {
                $_
            }
            # Return result
            $Output
        }
    }
}