function Confirm-FalconAdminCommand {
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
            $PSBoundParameters['sequence_id'] = 0
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
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/scripts/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:patch', Mandatory = $true,
            Position = 2)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Get-FalconPutFile {
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
        [int] $Offset,

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
        [int] $Offset,

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
function Invoke-FalconAdminCommand {
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
            [void] $PSBoundParameters.Remove('Arguments')
        } else {
            $PSBoundParameters.Command
        }
        $PSBoundParameters['command_string'] = $CommandString
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
function Remove-FalconPutFile {
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
function Send-FalconPutFile {
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/put-files/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/put-files/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
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
    [CmdletBinding(DefaultParameterSetName = '/real-time-response/entities/scripts/v1:post')]
    param(
        [Parameter(ParameterSetName = '/real-time-response/entities/scripts/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
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