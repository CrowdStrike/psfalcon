function Confirm-FalconAdminCommand {
<#
.SYNOPSIS
Verify the status of a Real-time Response 'admin' command issued to a single-host session
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.

Confirms the status of an executed 'admin' command. The single-host Real-time Response APIs require that commands
be confirmed to 'acknowledge' that they have been processed as part of your API-based workflow. Failing to confirm
after commands can lead to unexpected results.

A 'sequence_id' value of 0 is added if the parameter is not specified.
.PARAMETER SequenceId
Sequence identifier
.PARAMETER CloudRequestId
Command request identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/admin-command/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:get',Position=1)]
        [Alias('sequence_id')]
        [int32]$SequenceId,
        [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:get',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('cloud_request_id','task_id')]
        [string]$CloudRequestId
    )
    begin {
        if (!$PSBoundParameters.SequenceId) { $PSBoundParameters['SequenceId'] = 0 }
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('cloud_request_id','sequence_id') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Edit-FalconScript {
<#
.SYNOPSIS
Modify a Real-time Response script
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER Platform
Operating system platform
.PARAMETER PermissionType
Permission level [public: 'Administrators' and 'Active Responders', group: 'Administrators', private: creator]
.PARAMETER Name
Script name
.PARAMETER Description
Script description
.PARAMETER Comment
Audit log comment
.PARAMETER Path
Path to script file
.PARAMETER Id
Script identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/scripts/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:patch',
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidateSet('windows','mac','linux',IgnoreCase=$false)]
        [string[]]$Platform,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:patch',
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidateSet('private','group','public',IgnoreCase=$false)]
        [Alias('permission_type')]
        [string]$PermissionType,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:patch',
            ValueFromPipelineByPropertyName,Position=3)]
        [string]$Name,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:patch',
            ValueFromPipelineByPropertyName,Position=4)]
        [string]$Description,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:patch',
            ValueFromPipelineByPropertyName,Position=5)]
        [ValidateLength(1,4096)]
        [Alias('comments_for_audit_log')]
        [string]$Comment,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=6)]
        [Alias('content','FullName')]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
            }
        })]
        [string]$Path,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=7)]
        [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ ContentType = 'multipart/form-data' }
            Format = @{
                Formdata = @('id','platform','permission_type','name','description','comments_for_audit_log',
                    'content')
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconPutFile {
<#
.SYNOPSIS
Search for Real-time Response 'put' files
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER Id
'Put' file identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/queries/put-files/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/put-files/v2:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get',Position=3)]
        [ValidateRange(1,100)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','filter','limit') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -Inputs $PSBoundParameters }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconScript {
<#
.SYNOPSIS
Search for custom Real-time Response scripts
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER Id
Script identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/queries/scripts/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v2:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get',Position=3)]
        [ValidateRange(1,100)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','filter','limit') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -Inputs $PSBoundParameters }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Invoke-FalconAdminCommand {
<#
.SYNOPSIS
Issue a Real-time Response admin command to an existing single-host or batch session
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.

Sessions can be started using 'Start-FalconSession'. A successfully created session will contain a 'session_id'
or 'batch_id' value which can be used with the '-SessionId' or '-BatchId' parameters.

The 'Wait' parameter will use 'Confirm-FalconAdminCommand' or 'Confirm-FalconGetFile' to check for command
results every 5 seconds for a total of 60 seconds.
.PARAMETER Command
Real-time Response command
.PARAMETER Argument
Arguments to include with the command
.PARAMETER Timeout
Length of time to wait for a result, in seconds
.PARAMETER OptionalHostId
Restrict execution to specific host identifiers
.PARAMETER SessionId
Session identifier
.PARAMETER BatchId
Batch session identifier
.PARAMETER Wait
Use 'Confirm-FalconAdminCommand' or 'Confirm-FalconGetFile' to retrieve command results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:post',Mandatory,Position=1)]
        [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Mandatory,
            Position=1)]
        [ValidateSet('cat','cd','clear','cp','csrutil','cswindiag','encrypt','env','eventlog backup',
            'eventlog export','eventlog list','eventlog view','filehash','get','getsid','help','history',
            'ifconfig','ipconfig','kill','ls','map','memdump','mkdir','mount','mv','netstat','ps','put',
            'put-and-run','reg delete','reg load','reg query','reg set','reg unload','restart','rm','run',
            'runscript','shutdown','umount','unmap','update history','update install','update list',
            'update install','users','xmemdump','zip',IgnoreCase=$false)]
        [Alias('base_command')]
        [string]$Command,
        [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:post',Position=2)]
        [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Position=2)]
        [Alias('Arguments')]
        [string]$Argument,
        [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Position=3)]
        [ValidateRange(30,600)]
        [int32]$Timeout,
        [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Position=4)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('optional_hosts','OptionalHostIds')]
        [string[]]$OptionalHostId,
        [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:post',Mandatory,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('session_id')]
        [string]$SessionId,
        [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Mandatory,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('batch_id')]
        [string]$BatchId,
        [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:post')]
        [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post')]
        [switch]$Wait
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Format = @{
                Query = @('timeout')
                Body = @{ root = @('session_id','base_command','command_string','optional_hosts','batch_id') }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($OptionalHostId) { @($OptionalHostId).foreach{ $List.Add($_) }}}
    end {
        if ($PSBoundParameters.BatchId -and $PSBoundParameters.Command -eq 'get') {
            # Redirect to 'Invoke-FalconBatchGet' for multi-host 'get' requests
            $GetParam = @{
                FilePath = $PSBoundParameters.Argument
                BatchId = $PSBoundParameters.BatchId
                Wait = $PSBoundParameters.Wait
            }
            if ($Timeout) { $GetParam['Timeout'] = $PSBoundParameters.Timeout }
            if ($List) { $GetParam['OptionalHostId'] = @($List | Select-Object -Unique) }
            Invoke-FalconBatchGet @GetParam
        } else {
            # Verify 'Endpoint' using BatchId/SessionId
            [string]$Endpoint = if ($PSBoundParameters.BatchId) {
                if ($List) { $PSBoundParameters['OptionalHostId'] = @($List | Select-Object -Unique) }
                '/real-time-response/combined/batch-admin-command/v1:post'
            } elseif ($PSBoundParameters.SessionId) {
                '/real-time-response/entities/admin-command/v1:post'
            }
            $PSBoundParameters['command_string'] = if ($PSBoundParameters.Argument) {
                # Join 'Command' and 'Argument' into 'command_string'
                @($PSBoundParameters.Command,$PSBoundParameters.Argument) -join ' '
                [void]$PSBoundParameters.Remove('Argument')
            } else {
                $PSBoundParameters.Command
            }
            @(Invoke-Falcon @Param -Endpoint $Endpoint -Inputs $PSBoundParameters).foreach{
                if ($BatchId) {
                    # Add 'batch_id' to each result and output
                    Set-Property $_ batch_id $BatchId
                    $_
                } elseif ($SessionId -and $Wait) {
                    for ($i = 0; $i -lt 60 -and $Result.Complete -ne $true -and !$Result.sha256; $i += 5) {
                        # Attempt to 'confirm' for 60 seconds
                        Start-Sleep 5
                        $Result = if ($Command -eq 'get') {
                            $_ | Confirm-FalconGetFile
                        } else {
                            $_ | Confirm-FalconAdminCommand
                        }
                    }
                    $Result
                } else {
                    $_
                }
            }
        }
    }
}
function Remove-FalconPutFile {
<#
.SYNOPSIS
Remove a Real-time Response 'put' file
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER Id
Real-time Response 'put' file identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/put-files/v1:delete',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/put-files/v1:delete',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Remove-FalconScript {
<#
.SYNOPSIS
Remove a custom Real-time Response script
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER Id
Script identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/scripts/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Send-FalconPutFile {
<#
.SYNOPSIS
Upload a Real-time Response 'put' file
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER Name
File name
.PARAMETER Description
File description
.PARAMETER Comment
Comment for audit log
.PARAMETER Path
Path to local file
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/put-files/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/put-files/v1:post',
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/real-time-response/entities/put-files/v1:post',Position=2)]
        [string]$Description,
        [Parameter(ParameterSetName='/real-time-response/entities/put-files/v1:post',Position=3)]
        [ValidateLength(1,4096)]
        [Alias('comments_for_audit_log')]
        [string]$Comment,
        [Parameter(ParameterSetName='/real-time-response/entities/put-files/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=4)]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
            }
        })]
        [Alias('file','FullName')]
        [string]$Path
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ ContentType = 'multipart/form-data' }
            Format = @{ Formdata = @('file','name','description','comments_for_audit_log') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Send-FalconScript {
<#
.SYNOPSIS
Upload a custom Real-time Response script
.DESCRIPTION
Requires 'Real Time Response (Admin): Write'.
.PARAMETER Platform
Operating system platform
.PARAMETER PermissionType
Permission level [public: 'Administrators' and 'Active Responders', group: 'Administrators', private: creator]
.PARAMETER Name
Script name
.PARAMETER Description
Script description
.PARAMETER Comment
Audit log comment
.PARAMETER Path
Path to local file or string-based script content
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/scripts/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidateSet('windows','mac','linux',IgnoreCase=$false)]
        [string[]]$Platform,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidateSet('private','group','public',IgnoreCase=$false)]
        [Alias('permission_type')]
        [string]$PermissionType,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [string]$Name,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [string]$Description,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:post',ValueFromPipelineByPropertyName,
            Position=5)]
        [ValidateLength(1,4096)]
        [Alias('comments_for_audit_log')]
        [string]$Comment,
        [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=6)]
        [Alias('content','FullName')]
        [string]$Path
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ ContentType = 'multipart/form-data' }
            Format = @{
                Formdata = @('platform','permission_type','name','description','comments_for_audit_log',
                    'content')
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}