function Confirm-FalconCommand {
<#
.Synopsis
Get status of an executed read-only command on a single host
.Parameter CloudRequestId
Real-time Response command request identifier
.Parameter SequenceId
Sequence identifier
.Role
real-time-response:read
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/command/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/command/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $CloudRequestId,

        [Parameter(ParameterSetName = '/real-time-response/entities/command/v1:get', Position = 2)]
        [int] $SequenceId
    )
    begin {
        if (!$PSBoundParameters.SequenceId) {
            $PSBoundParameters.Add('sequence_id', 0)
        }
        $Fields = @{
            CloudRequestId = 'cloud_request_id'
            SequenceId     = 'sequence_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud_request_id', 'sequence_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Confirm-FalconGetFile {
<#
.Synopsis
Check the status of a Real-time Response 'get' command request
.Parameter SessionId
Real-time Response session identifier
.Parameter BatchGetCmdReqId
Batch Real-time Response 'get' command identifier
.Parameter Timeout
Length of time to wait for a result, in seconds
.Role
real-time-response:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/file/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/file/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SessionId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-get-command/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $BatchGetCmdReqId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-get-command/v1:get', Position = 2)]
        [ValidateRange(30,600)]
        [int] $Timeout
    )
    begin {
        $Fields = @{
            BatchGetCmdReqId = 'batch_get_cmd_req_id'
            SessionId        = 'session_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id', 'batch_get_cmd_req_id', 'timeout', 'timeout_duration')
            }
        }
    }
    process {
        $Request = Invoke-Falcon @Param
        if ($PSCmdlet.ParameterSetName -eq '/real-time-response/combined/batch-get-command/v1:get') {
            $Request.PSObject.Properties | ForEach-Object {
                $Aid = $_.Name
                ($_.Value).PSObject.Properties.Add((New-Object PSNoteProperty('aid', $Aid)))
                $_.Value
            }
        } else {
            $Request
        }
    }
}
function Confirm-FalconResponderCommand {
<#
.Synopsis
Get status of an executed active-responder command on a single host
.Parameter CloudRequestId
Real-time Response command request identifier
.Parameter SequenceId
Sequence identifier
.Role
real-time-response:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/active-responder-command/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/active-responder-command/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $CloudRequestId,

        [Parameter(ParameterSetName = '/real-time-response/entities/active-responder-command/v1:get',
            Position = 2)]
        [int] $SequenceId
    )
    begin {
        if (!$PSBoundParameters.SequenceId) {
            $PSBoundParameters.Add('sequence_id', 0)
        }
        $Fields = @{
            CloudRequestId = 'cloud_request_id'
            SequenceId     = 'sequence_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud_request_id', 'sequence_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconSession {
<#
.Synopsis
Search for Real-time Response sessions
.Parameter Ids
Real-time Response session identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Parameter Queue
Restrict search to sessions that have been queued
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
real-time-response:read
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/queries/sessions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/queued-sessions/GET/v1:post',
            Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/real-time-response/entities/sessions/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 4)]
        [ValidateRange(1,100)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 3)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/real-time-response/entities/queued-sessions/GET/v1:post',
            Mandatory = $true)]
        [array] $Queue,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get')]
        [switch] $Total

    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'limit', 'filter')
                Body  = @{
                    root = @('ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconBatchGet {
<#
.Synopsis
Issue a Real-time Response batch 'get' command to an existing batch session
.Parameter BatchId
Batch Real-time Response session identifier
.Parameter FilePath
Path to file on target Host(s)
.Parameter OptionalHostIds
Restrict execution to specific Host identifier(s)
.Parameter Timeout
Length of time to wait for a result, in seconds
.Role
real-time-response:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/combined/batch-get-command/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-get-command/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $BatchId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-get-command/v1:post', Mandatory = $true,
            Position = 2)]
        [string] $FilePath,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-get-command/v1:post', Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [array] $OptionalHostIds,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-get-command/v1:post', Position = 4)]
        [ValidateRange(30,600)]
        [int] $Timeout
    )
    begin {
        $Fields = @{
            BatchId         = 'batch_id'
            FilePath        = 'file_path'
            OptionalHostIds = 'optional_hosts'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('timeout')
                Body  = @{
                    root = @('batch_id', 'file_path', 'optional_hosts')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconCommand {
<#
.Synopsis
Issue a Real-time Response read-only command to an existing single-host or batch session
.Parameter SessionId
Real-time Response session identifier
.Parameter BatchId
Batch Real-time Response session identifier
.Parameter Command
Real-time Response command
.Parameter Arguments
Arguments to include with the command
.Parameter OptionalHostIds
Restrict execution to specific Host identifier(s)
.Parameter Timeout
Length of time to wait for a result, in seconds
.Role
real-time-response:read
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/command/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/command/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SessionId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-command/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $BatchId,

        [Parameter(ParameterSetName = '/real-time-response/entities/command/v1:post', Mandatory = $true,
            Position = 2)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-command/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidateSet('cat', 'cd', 'clear', 'csrutil', 'env', 'eventlog', 'filehash', 'getsid', 'help', 'history',
            'ifconfig', 'ipconfig', 'ls', 'mount', 'netstat', 'ps', 'reg query', 'users')]
        [string] $Command,

        [Parameter(ParameterSetName = '/real-time-response/entities/command/v1:post', Position = 3)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-command/v1:post', Position = 3)]
        [string] $Arguments,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-command/v1:post', Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [array] $OptionalHostIds,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-command/v1:post', Position = 5)]
        [ValidateRange(30,600)]
        [int] $Timeout
    )
    begin {
        $CommandString = if ($PSBoundParameters.Arguments) {
            @($PSBoundParameters.Command, $PSBoundParameters.Arguments) -join ' '
            $PSBoundParameters.Remove('Arguments')
        } else {
            $PSBoundParameters.Command
        }
        [void] $PSBoundParameters.Add('command_string', $CommandString)
        $Fields = @{
            BatchId         = 'batch_id'
            Command         = 'base_command'
            OptionalHostIds = 'optional_hosts'
            SessionId       = 'session_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('timeout')
                Body  = @{
                    root = @('session_id', 'base_command', 'command_string', 'optional_hosts', 'batch_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconResponderCommand {
<#
.Synopsis
Issue a Real-time Response active-responder command to an existing single-host or batch session
.Parameter SessionId
Real-time Response session identifier
.Parameter BatchId
Batch Real-time Response session identifier
.Parameter Command
Real-time Response command
.Parameter Arguments
Arguments to include with the command
.Parameter OptionalHostIds
Restrict execution to specific Host identifier(s)
.Parameter Timeout
Length of time to wait for a result, in seconds
.Role
real-time-response:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/active-responder-command/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/active-responder-command/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SessionId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-active-responder-command/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $BatchId,

        [Parameter(ParameterSetName = '/real-time-response/entities/active-responder-command/v1:post',
            Mandatory = $true, Position = 2)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-active-responder-command/v1:post',
            Mandatory = $true, Position = 2)]
        [ValidateSet('cat', 'cd', 'clear', 'cp', 'csrutil', 'encrypt', 'env', 'eventlog', 'filehash', 'getsid',
            'help', 'history', 'ifconfig', 'ipconfig', 'kill', 'ls', 'map', 'memdump', 'mkdir', 'mount', 'mv',
            'netstat', 'ps', 'reg delete', 'reg load', 'reg query', 'reg set', 'reg unload', 'restart', 'rm',
            'runscript', 'shutdown', 'umount', 'unmap', 'update history', 'update install', 'update list',
            'update install', 'users', 'xmemdump', 'zip')]
        [string] $Command,

        [Parameter(ParameterSetName = '/real-time-response/entities/active-responder-command/v1:post',
            Position = 3)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-active-responder-command/v1:post',
            Position = 3)]
        [string] $Arguments,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-active-responder-command/v1:post',
            Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [array] $OptionalHostIds,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-active-responder-command/v1:post',
            Position = 5)]
        [ValidateRange(30,600)]
        [int] $Timeout
    )
    begin {
        $CommandString = if ($PSBoundParameters.Arguments) {
            @($PSBoundParameters.Command, $PSBoundParameters.Arguments) -join ' '
            $PSBoundParameters.Remove('Arguments')
        } else {
            $PSBoundParameters.Command
        }
        [void] $PSBoundParameters.Add('command_string', $CommandString)
        $Fields = @{
            BatchId         = 'batch_id'
            Command         = 'base_command'
            OptionalHostIds = 'optional_hosts'
            SessionId       = 'session_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('timeout')
                Body  = @{
                    root = @('session_id', 'base_command', 'command_string', 'optional_hosts', 'batch_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconGetFile {
<#
.Synopsis
Download a Real-time Response 'get' file
.Parameter Sha256
Sha256 hash value of file to download
.Parameter SessionId
Real-time Response session identifier
.Parameter Path
Destination path
.Role
real-time-response:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/extracted-file-contents/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/extracted-file-contents/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [string] $Sha256,

        [Parameter(ParameterSetName = '/real-time-response/entities/extracted-file-contents/v1:get',
            Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SessionId,

        [Parameter(ParameterSetName = '/real-time-response/entities/extracted-file-contents/v1:get',
            Mandatory = $true, Position = 3)]
        [ValidatePattern('^*\.7z$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    begin {
        $Fields = @{
            SessionId = 'session_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                Accept = 'application/x-7z-compressed'
            }
            Format   = @{
                Query   = @('session_id', 'sha256')
                Outfile = 'path'
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconCommand {
<#
.Synopsis
Remove a Real-time Response command from a queued session
.Parameter SessionId
Real-time Response session identifier
.Parameter CloudRequestId
Cloud request identifier
.Role
real-time-response:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/queued-sessions/command/v1:delete',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SessionId,

        [Parameter(ParameterSetName = '/real-time-response/entities/queued-sessions/command/v1:delete',
            Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $CloudRequestId
    )
    begin {
        $Fields = @{
            CloudRequestId = 'cloud_request_id'
            SessionId      = 'session_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id', 'cloud_request_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconGetFile {
<#
.Synopsis
Remove Real-time Response 'get' files
.Parameter SessionId
Real-time Response session identifier
.Parameter Id
Real-time Response 'get' file Sha256 value
.Role
real-time-response:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/file/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/file/v1:delete',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SessionId,

        [Parameter(ParameterSetName = '/real-time-response/entities/file/v1:delete',
            Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{64}$')]
        [string] $Id
    )
    begin {
        $Fields = @{
            Id        = 'ids'
            SessionId = 'session_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id', 'ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconSession {
<#
.Synopsis
Delete a session.
.Parameter Id
Real-time Response session identifier
.Role
real-time-response:read
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/sessions/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/sessions/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id
    )
    begin {
        $Fields = @{
            Id = 'session_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Start-FalconSession {
<#
.Synopsis
Initialize a single-host or batch Real-time Response session
.Parameter HostId
Host identifier
.Parameter HostIds
Host identifiers
.Parameter Timeout
Length of time to wait for a result, in seconds
.Parameter ExistingBatchId
Add hosts to an existing batch Real-time Response session
.Parameter QueueOffline
Add non-responsive hosts to the offline queue
.Role
real-time-response:read
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/sessions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/sessions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $HostId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-init-session/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-init-session/v1:post', Position = 2)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-init-session/v1:post', Position = 3)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $ExistingBatchId,

        [Parameter(ParameterSetName = '/real-time-response/entities/sessions/v1:post', Position = 2)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-init-session/v1:post', Position = 4)]
        [boolean] $QueueOffline
    )
    begin {
        $Fields = @{
            ExistingBatchId = 'existing_batch_id'
            HostId          = 'device_id'
            HostIds         = 'host_ids'
            QueueOffline    = 'queue_offline'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('timeout')
                Body  = @{
                    root = @('existing_batch_id', 'host_ids', 'queue_offline', 'device_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}

function Update-FalconSession {
<#
.Synopsis
Refresh a single-host or batch Real-time Response session to prevent expiration
.Parameter HostId
Host identifier
.Parameter BatchId
Real-time Response batch session identifier
.Parameter Timeout
Length of time to wait for a result, in seconds
.Parameter HostsToRemove
Host identifier(s) to remove from the batch Real-time Response session
.Parameter QueueOffline
Add non-responsive hosts to the offline queue
.Role
real-time-response:read
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/refresh-session/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/refresh-session/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $HostId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-refresh-session/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $BatchId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-refresh-session/v1:post', Position = 2)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-refresh-session/v1:post', Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostsToRemove,

        [Parameter(ParameterSetName = '/real-time-response/entities/refresh-session/v1:post', Position = 2)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-refresh-session/v1:post', Position = 4)]
        [boolean] $QueueOffline
    )
    begin {
        $Fields = @{
            BatchId       = 'batch_id'
            HostId        = 'device_id'
            HostsToRemove = 'hosts_to_remove'
            QueueOffline  = 'queue_offline'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('timeout')
                Body  = @{
                    root = @('queue_offline', 'device_id', 'batch_id', 'hosts_to_remove')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}