function Confirm-FalconAdminCommand {
<#
.Synopsis
Get status of an executed admin command on a single host
.Parameter CloudRequestId
Real-time Response command request identifier
.Parameter SequenceId
Sequence identifier
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/admin-command/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/admin-command/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $CloudRequestId,

        [Parameter(ParameterSetName = '/real-time-response/entities/admin-command/v1:get', Position = 2)]
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
function Edit-FalconScript {
<#
.Synopsis
Modify a Real-time Response script
.Parameter Id
Real-time Response script identifier
.Parameter Path
Path to script file
.Parameter Platform
Operating System platform
.Parameter PermissionType
Real-time Response script permission level
.Parameter Name
Real-time Response script name
.Parameter Description
Real-time Response script description
.Parameter Comment
Audit log comment
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/scripts/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Mandatory = $true,
            Position = 2)]
        [ValidateScript({
            if (Test-Path $_) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist."
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Position = 3)]
        [ValidateSet('windows', 'mac', 'linux')]
        [array] $Platform,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Position = 4)]
        [ValidateSet('private', 'group', 'public')]
        [string] $PermissionType,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Position = 5)]
        [string] $Name,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Position = 6)]
        [string] $Description,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Position = 7)]
        [ValidateLength(1,4096)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            Comment        = 'comments_for_audit_log'
            Path           = 'content'
            PermissionType = 'permission_type'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'multipart/form-data'
            }
            Format   = @{
                Formdata = @('id', 'platform', 'permission_type', 'name', 'description', 'comments_for_audit_log',
                    'content')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconPutFile {
<#
.Synopsis
Search for Real-time Response 'put' files
.Parameter Ids
One or more 'put' file identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/queries/put-files/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/put-files/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/real-time-response/queries/put-files/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/real-time-response/queries/put-files/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/real-time-response/queries/put-files/v1:get', Position = 3)]
        [ValidateRange(1,100)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/real-time-response/queries/put-files/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/real-time-response/queries/put-files/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/real-time-response/queries/put-files/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/real-time-response/queries/put-files/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconScript {
<#
.Synopsis
Search for custom Real-time Response scripts
.Parameter Ids
One or more custom Real-time Response script identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/queries/scripts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/real-time-response/queries/scripts/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/real-time-response/queries/scripts/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/real-time-response/queries/scripts/v1:get', Position = 3)]
        [ValidateRange(1,100)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/real-time-response/queries/scripts/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/real-time-response/queries/scripts/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/real-time-response/queries/scripts/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/real-time-response/queries/scripts/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
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
One or more Real-time Response session identifiers
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
function Invoke-FalconAdminCommand {
<#
.Synopsis
Issue a Real-time Response admin command to an existing single-host or batch session
.Parameter SessionId
Real-time Response session identifier
.Parameter BatchId
Batch Real-time Response session identifier
.Parameter Command
Real-time Response command
.Parameter Arguments
Arguments to include with the command
.Parameter OptionalHostIds
Restrict execution to specific Host identifiers
.Parameter Timeout
Length of time to wait for a result, in seconds
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/admin-command/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/admin-command/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SessionId,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-admin-command/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $BatchId,

        [Parameter(ParameterSetName = '/real-time-response/entities/admin-command/v1:post', Mandatory = $true,
            Position = 2)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-admin-command/v1:post',
            Mandatory = $true, Position = 2)]
        [ValidateSet('cat', 'cd', 'clear', 'cp', 'csrutil', 'encrypt', 'env', 'eventlog', 'filehash', 'get',
            'getsid', 'help', 'history', 'ifconfig', 'ipconfig', 'kill', 'ls', 'map', 'memdump', 'mkdir',
            'mount', 'mv', 'netstat', 'ps', 'put', 'reg delete', 'reg load', 'reg query', 'reg set', 'reg unload',
            'restart', 'rm', 'run', 'runscript', 'shutdown', 'umount', 'unmap', 'update history',
            'update install', 'update list', 'update install', 'users', 'xmemdump', 'zip')]
        [string] $Command,

        [Parameter(ParameterSetName = '/real-time-response/entities/admin-command/v1:post', Position = 3)]
        [Parameter(ParameterSetName = '/real-time-response/combined/batch-admin-command/v1:post', Position = 3)]
        [string] $Arguments,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-admin-command/v1:post', Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [array] $OptionalHostIds,

        [Parameter(ParameterSetName = '/real-time-response/combined/batch-admin-command/v1:post', Position = 5)]
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
function Invoke-FalconBatchGet {
<#
.Synopsis
Issue a Real-time Response batch 'get' command to an existing batch session
.Parameter BatchId
Batch Real-time Response session identifier
.Parameter FilePath
Path to file on target Host(s)
.Parameter OptionalHostIds
Restrict execution to specific Host identifiers
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
Restrict execution to specific Host identifiers
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
Restrict execution to specific Host identifiers
.Parameter Timeout
Length of time to wait for a result, in seconds
.Role
real-time-response-admin:write
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
function Remove-FalconPutFile {
<#
.Synopsis
Remove Real-time Response 'put' files
.Parameter Id
Real-time Response 'put' file identifier
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/put-files/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/put-files/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [string] $Id
    )
    begin {
        $Fields = @{
            Id = 'ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconScript {
<#
.Synopsis
Remove custom Real-time Response scripts
.Parameter Id
Real-time Response script identifier
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/scripts/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [string] $Id
    )
    begin {
        $Fields = @{
            Id = 'ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids')
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
function Send-FalconPutFile {
<#
.Synopsis
Upload a Real-time Response 'put' file
.Parameter Path
Path to local file
.Parameter Name
Real-time Response 'put' file name
.Parameter Description
Real-time Response 'put' file description
.Parameter Comment
Comment for audit log
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/put-files/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/put-files/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateScript({
            if (Test-Path $_) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist."
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = '/real-time-response/entities/put-files/v1:post', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/real-time-response/entities/put-files/v1:post', Position = 3)]
        [string] $Description,

        [Parameter(ParameterSetName = '/real-time-response/entities/put-files/v1:post', Position = 4)]
        [ValidateLength(1,4096)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            Comment = 'comments_for_audit_log'
            Path    = 'file'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'multipart/form-data'
            }
            Format   = @{
                Formdata = @('file', 'name', 'description', 'comments_for_audit_log')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Send-FalconScript {
<#
.Synopsis
Upload a custom Real-time Response script
.Parameter Path
Path to local file
.Parameter Platform
Operating System platform
.Parameter PermissionType
Real-time Response script permission level
.Parameter Name
Real-time Response script name
.Parameter Description
Real-time Response script description
.Parameter Comment
Audit log comment
.Role
real-time-response-admin:write
#>
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/scripts/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateScript({
            if (Test-Path $_) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist."
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidateSet('windows', 'mac', 'linux')]
        [array] $Platform,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:post', Mandatory = $true,
            Position = 3)]
        [ValidateSet('private', 'group', 'public')]
        [string] $PermissionType,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:post', Position = 4)]
        [string] $Name,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:post', Position = 5)]
        [string] $Description,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:post', Position = 6)]
        [ValidateLength(1,4096)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            Comment        = 'comments_for_audit_log'
            Path           = 'content'
            PermissionType = 'permission_type'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'multipart/form-data'
            }
            Format   = @{
                Formdata = @('platform', 'permission_type', 'name', 'description', 'comments_for_audit_log',
                    'content')
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
One or more host identifiers
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
Host identifiers to remove from the batch Real-time Response session
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
            Headers  = @{
                ContentType = 'application/json'
            }
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