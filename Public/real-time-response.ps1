function Confirm-FalconCommand {
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
        $Fields = @{
            CloudRequestId = 'cloud_request_id'
            SequenceId     = 'sequence_id'
        }
    }
    process {
        if (!$PSBoundParameters.SequenceId) {
            $PSBoundParameters['sequence_id'] = 0
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud_request_id', 'sequence_id')
            }
        }
        Invoke-Falcon @Param
    }
}
function Confirm-FalconGetFile {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id', 'batch_get_cmd_req_id', 'timeout', 'timeout_duration')
            }
        }
        $Request = Invoke-Falcon @Param
        if ($PSCmdlet.ParameterSetName -eq '/real-time-response/combined/batch-get-command/v1:get') {
            @($Request.PSObject.Properties).foreach{
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
        $Fields = @{
            CloudRequestId = 'cloud_request_id'
            SequenceId     = 'sequence_id'
        }
    }
    process {
        if (!$PSBoundParameters.SequenceId) {
            $PSBoundParameters['sequence_id'] = 0
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud_request_id', 'sequence_id')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconSession {
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/queries/sessions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/queued-sessions/GET/v1:post',
            Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/real-time-response/entities/sessions/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 4)]
        [ValidateRange(1,100)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get', Position = 3)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/real-time-response/entities/queued-sessions/GET/v1:post',
            Mandatory = $true)]
        [switch] $Queue,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/real-time-response/queries/sessions/v1:get')]
        [switch] $Total

    )
    process {
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
        Invoke-Falcon @Param
    }
}
function Invoke-FalconBatchGet {
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
    }
    process {
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
        $Request = Invoke-Falcon @Param
        if ($Request.batch_id -and $Request.combined.resources) {
            [PSCustomObject] @{
                batch_get_cmd_req_id = $Request.batch_get_cmd_req_id
                hosts                = $Request.combined.resources.PSObject.Properties.Value
            }
        } else {
            $Request
        }
    }
}
function Invoke-FalconCommand {
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
        $Fields = @{
            BatchId         = 'batch_id'
            Command         = 'base_command'
            OptionalHostIds = 'optional_hosts'
            SessionId       = 'session_id'
        }
    }
    process {
        $CommandString = if ($PSBoundParameters.Arguments) {
            @($PSBoundParameters.Command, $PSBoundParameters.Arguments) -join ' '
            [void] $PSBoundParameters.Remove('Arguments')
        } else {
            $PSBoundParameters.Command
        }
        $PSBoundParameters['command_string'] = $CommandString
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
        Invoke-Falcon @Param
    }
}
function Invoke-FalconResponderCommand {
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
        $Fields = @{
            BatchId         = 'batch_id'
            Command         = 'base_command'
            OptionalHostIds = 'optional_hosts'
            SessionId       = 'session_id'
        }
    }
    process {
        $CommandString = if ($PSBoundParameters.Arguments) {
            @($PSBoundParameters.Command, $PSBoundParameters.Arguments) -join ' '
            [void] $PSBoundParameters.Remove('Arguments')
        } else {
            $PSBoundParameters.Command
        }
        $PSBoundParameters['command_string'] = $CommandString
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
        Invoke-Falcon @Param
    }
}
function Receive-FalconGetFile {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Remove-FalconCommand {
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/queued-sessions/command/v1:delete')]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id', 'cloud_request_id')
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconGetFile {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id', 'ids')
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconSession {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('session_id')
            }
        }
        Invoke-Falcon @Param
    }
}
function Start-FalconSession {
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/sessions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/sessions/v1:post', Mandatory = $true,
            ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
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
    }
    process {
        if ($PSBoundParameters.HostIds -and ($PSBoundParameters.HostIds | Measure-Object).Count -gt 10000) {
            throw "Real-time Response sessions are limited to 10,000 hosts."
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
        $Request = Invoke-Falcon @Param
        if ($Request.batch_id -and $Request.resources) {
            [PSCustomObject] @{
                batch_id = $Request.batch_id
                hosts    = $Request.resources.PSObject.Properties.Value
            }
        } else {
            $Request
        }
    }
}
function Update-FalconSession {
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/refresh-session/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/refresh-session/v1:post', Mandatory = $true,
            ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}