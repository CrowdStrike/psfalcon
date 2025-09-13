function Confirm-FalconAdminCommand {
<#
.SYNOPSIS
Verify the status of a Real-time Response 'admin' command issued to a single-host session
.DESCRIPTION
Confirms the status of an executed 'admin' command. The single-host Real-time Response APIs require that commands
be confirmed to 'acknowledge' that they have been processed as part of your API-based workflow. Failing to confirm
after commands can lead to unexpected results.

A 'sequence_id' value of 0 is added if the parameter is not specified.

Requires 'Real time response (admin): Write'.
.PARAMETER SequenceId
Sequence identifier
.PARAMETER CloudRequestId
Command request identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Confirm-FalconAdminCommand
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/admin-command/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:get',Position=1)]
    [Alias('sequence_id')]
    [int32]$SequenceId,
    [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('cloud_request_id','task_id')]
    [string]$CloudRequestId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    if (!$PSBoundParameters.SequenceId) { $PSBoundParameters['SequenceId'] = 0 }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Confirm-FalconCommand {
<#
.SYNOPSIS
Verify the status of a Real-time Response 'read-only' command issued to a single-host session
.DESCRIPTION
Confirms the status of an executed 'read-only' command. The single-host Real-time Response APIs require that
commands be confirmed to 'acknowledge' that they have been processed as part of your API-based workflow. Failing
to confirm after commands can lead to unexpected results.

A 'sequence_id' value of 0 is added if the parameter is not specified.

Requires 'Real time response: Read'.
.PARAMETER SequenceId
Sequence identifier
.PARAMETER CloudRequestId
Command request identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Confirm-FalconCommand
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/command/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/command/v1:get',Position=1)]
    [Alias('sequence_id')]
    [int32]$SequenceId,
    [Parameter(ParameterSetName='/real-time-response/entities/command/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('cloud_request_id','task_id')]
    [string]$CloudRequestId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    if (!$PSBoundParameters.SequenceId) { $PSBoundParameters['sequence_id'] = 0 }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Confirm-FalconGetFile {
<#
.SYNOPSIS
Verify the status of a Real-time Response 'get' command
.DESCRIPTION
Requires 'Real time response: Write'.
.PARAMETER SessionId
Session identifier
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 30]
.PARAMETER BatchGetCmdReqId
Batch 'get' command identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Confirm-FalconGetFile
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/combined/batch-get-command/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/file/v2:get',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$SessionId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:get',Position=1)]
    [ValidateRange(1,600)]
    [int32]$Timeout,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:get',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('batch_get_cmd_req_id')]
    [string]$BatchGetCmdReqId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name }}
  process {
    # Verify 'Endpoint' using SessionId/BatchGetCmdReqId
    $Endpoint = if ($PSBoundParameters.SessionId) {
      '/real-time-response/entities/file/v2:get'
    } else {
      '/real-time-response/combined/batch-get-command/v1:get'
    }
    @(Invoke-Falcon @Param -Endpoint $Endpoint -UserInput $PSBoundParameters).foreach{
      if ($BatchGetCmdReqId) {
        $_.PSObject.Properties | ForEach-Object {
          # Append 'aid' and 'batch_get_cmd_req_id' to each host result and output
          Set-Property $_.Value aid $_.Name
          Set-Property $_.Value batch_get_cmd_req_id $BatchGetCmdReqId
          $_.Value
        }
      } else {
        $_
      }
    }
  }
}
function Confirm-FalconResponderCommand {
<#
.SYNOPSIS
Verify the status of a Real-time Response 'active-responder' command issued to a single-host session
.DESCRIPTION
Confirms the status of an executed 'active-responder' command. The single-host Real-time Response APIs require
that commands be confirmed to 'acknowledge' that they have been processed as part of your API-based workflow.
Failing to confirm after commands can lead to unexpected results.

A 'sequence_id' value of 0 is added if the parameter is not specified.

Requires 'Real time response: Write'.
.PARAMETER SequenceId
Sequence identifier
.PARAMETER CloudRequestId
Command request identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Confirm-FalconResponderCommand
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/active-responder-command/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/active-responder-command/v1:get',Position=1)]
    [Alias('sequence_id')]
    [int32]$SequenceId,
    [Parameter(ParameterSetName='/real-time-response/entities/active-responder-command/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('cloud_request_id','task_id')]
    [string]$CloudRequestId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    if (!$PSBoundParameters.SequenceId) { $PSBoundParameters['sequence_id'] = 0 }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconScript {
<#
.SYNOPSIS
Modify a Real-time Response script
.DESCRIPTION
Requires 'Real time response (admin): Write'.
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
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconScript
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
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconLibraryScript {
<#
.SYNOPSIS
Search for scripts in the 'falconscript' library
.DESCRIPTION
Requires 'Real time response (admin): Write'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconLibraryScript
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/queries/falcon-scripts/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/falcon-scripts/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/real-time-response/queries/falcon-scripts/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/real-time-response/queries/falcon-scripts/v1:get',Position=2)]
    [ValidateSet('modified_timestamp.asc','modified_timestamp.desc','name.asc','name.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/real-time-response/queries/falcon-scripts/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/real-time-response/queries/falcon-scripts/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/real-time-response/queries/falcon-scripts/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/real-time-response/queries/falcon-scripts/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/real-time-response/queries/falcon-scripts/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconPutFile {
<#
.SYNOPSIS
Search for Real-time Response 'put' files
.DESCRIPTION
Requires 'Real time response (admin): Write'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconPutFile
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/queries/put-files/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/put-files/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/real-time-response/queries/put-files/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 200
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconScript {
<#
.SYNOPSIS
Search for custom Real-time Response scripts
.DESCRIPTION
Requires 'Real time response (admin): Write'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconScript
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/queries/scripts/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/scripts/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/real-time-response/queries/scripts/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconSession {
<#
.SYNOPSIS
Search for Real-time Response sessions
.DESCRIPTION
Real-time Response sessions are segmented by permission, meaning that only sessions that were created using
your OAuth2 API Client will be visible. Use the 'Cid' switch to enable viewing of sessions from your entire
environment.

'Get-FalconQueue' can be used to find and export information about sessions in the 'offline queue'.

Requires 'Real time response: Read', and 'Real time response audit: Read' when using the 'Cid' switch.
.PARAMETER Id
Session identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER WithCommandInfo
Include executed command detail when displaying all sessions in the environment
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Cid
Expand search to include all sessions created within your environment
.PARAMETER Queue
Restrict search to sessions that have been queued
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSession
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/queries/sessions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/queued-sessions/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Parameter(ParameterSetName='/real-time-response/entities/sessions/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/real-time-response/queries/sessions/v1:get',Position=1)]
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/real-time-response/queries/sessions/v1:get',Position=2)]
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/real-time-response/queries/sessions/v1:get',Position=3)]
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get',Position=4)]
    [Alias('with_command_info')]
    [boolean]$CommandInfo,
    [Parameter(ParameterSetName='/real-time-response/queries/sessions/v1:get')]
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get',Mandatory)]
    [switch]$Cid,
    [Parameter(ParameterSetName='/real-time-response/entities/queued-sessions/GET/v1:post',Mandatory)]
    [switch]$Queue,
    [Parameter(ParameterSetName='/real-time-response/queries/sessions/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/real-time-response/queries/sessions/v1:get')]
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/real-time-response/queries/sessions/v1:get')]
    [Parameter(ParameterSetName='/real-time-response-audit/combined/sessions/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Invoke-FalconAdminCommand {
<#
.SYNOPSIS
Issue a Real-time Response admin command to an existing single-host or batch session
.DESCRIPTION
Sessions can be started using 'Start-FalconSession'. A successfully created session will contain a 'session_id'
or 'batch_id' value which can be used with the '-SessionId' or '-BatchId' parameters.

The 'Wait' parameter will use 'Confirm-FalconAdminCommand' or 'Confirm-FalconGetFile' to check for command
results every 20 seconds until complete or processing ends.

Requires 'Real time response (admin): Write'.
.PARAMETER Command
Real-time Response command
.PARAMETER Argument
Arguments to include with the command
.PARAMETER OptionalHostId
Restrict execution to specific host identifiers
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 30]
.PARAMETER HostTimeout
Length of time to wait for a result from target host(s), in seconds
.PARAMETER SessionId
Session identifier
.PARAMETER BatchId
Batch session identifier
.PARAMETER Wait
Use 'Confirm-FalconAdminCommand' or 'Confirm-FalconGetFile' to retrieve command result
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconAdminCommand
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:post',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Mandatory,
      Position=1)]
    [ValidateSet('cat','cd','clear','cp','csrutil','cswindiag','encrypt','env','eventlog backup','eventlog export',
      'eventlog list','eventlog view','falconscript','filehash','get','getsid','help','history','ifconfig',
      'ipconfig','kill','ls','map','memdump','mkdir','mount','mv','netstat','ps','put','put-and-run','reg delete',
      'reg load','reg query','reg set','reg unload','restart','rm','run','runscript','shutdown','tar','umount',
      'unmap','update history','update install','update list','update query','users','xmemdump','zip',
      IgnoreCase=$false)]
    [Alias('base_command')]
    [string]$Command,
    [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:post',Position=2)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Position=2)]
    [Alias('Arguments')]
    [string]$Argument,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('optional_hosts','OptionalHostIds')]
    [string[]]$OptionalHostId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Position=4)]
    [ValidateRange(1,600)]
    [int32]$Timeout,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Position=5)]
    [ValidateRange(1,600)]
    [Alias('host_timeout_duration')]
    [int32]$HostTimeout,
    [Parameter(ParameterSetName='/real-time-response/entities/admin-command/v1:post',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$SessionId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-admin-command/v1:post',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
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
        Query = @('timeout','host_timeout_duration')
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
      if ($List) { $GetParam['OptionalHostId'] = @($List) }
      Invoke-FalconBatchGet @GetParam
    } else {
      # Verify 'Endpoint' using BatchId/SessionId
      [string]$Endpoint = if ($PSBoundParameters.BatchId) {
        if ($List) { $PSBoundParameters['OptionalHostId'] = @($List) }
        '/real-time-response/combined/batch-admin-command/v1:post'
      } elseif ($PSBoundParameters.SessionId) {
        '/real-time-response/entities/admin-command/v1:post'
      }
      if ($Endpoint) {
        if ($PSBoundParameters.HostTimeout) {
          # Add 's' to denote seconds for 'host_timeout_duration'
          $PSBoundParameters.HostTimeout = [string]::Concat($PSBoundParameters.HostTimeout,'s')
        }
        $PSBoundParameters['command_string'] = if ($PSBoundParameters.Argument) {
          # Join 'Command' and 'Argument' into 'command_string'
          @($PSBoundParameters.Command,$PSBoundParameters.Argument) -join ' '
          [void]$PSBoundParameters.Remove('Argument')
        } else {
          $PSBoundParameters.Command
        }
        foreach ($Request in (Invoke-Falcon @Param -Endpoint $Endpoint -UserInput $PSBoundParameters)) {
          if ($BatchId -and @($Request.PSObject.Properties.Value).Where({$_.session_id})) {
            $Request = @($Request.PSObject.Properties.Value).Where({$_.session_id}).foreach{
              # Append 'batch_id' to command results with a 'session_id'
              Set-Property $_ batch_id $BatchId
              $_
            }
          }
          if ($Wait -and $Command -eq 'get') {
            Wait-RtrGet $Request $MyInvocation.MyCommand.Name
          } elseif ($Wait -and $SessionId) {
            Wait-RtrCommand $Request $MyInvocation.MyCommand.Name
          } else {
            $Request
          }
        }
      }
    }
  }
}
function Invoke-FalconBatchGet {
<#
.SYNOPSIS
Issue a Real-time Response batch 'get' command to an existing batch session
.DESCRIPTION
When a 'get' command has been issued, the 'batch_get_cmd_req_id' property will be returned. That value is used
to verify the completion of the file transfer using 'Confirm-FalconGetFile'.

The 'Wait' parameter will use 'Confirm-FalconGetFile' to check for command results every 20 seconds until complete
or processing ends.

Requires 'Real time response: Write'.
.PARAMETER FilePath
Path to file on target host
.PARAMETER OptionalHostId
Restrict execution to specific host identifiers
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 30]
.PARAMETER HostTimeout
Length of time to wait for a result from target host(s), in seconds
.PARAMETER BatchId
Batch session identifier
.PARAMETER Wait
Use 'Confirm-FalconGetFile' to retrieve command result
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconBatchGet
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/combined/batch-get-command/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:post',Mandatory,Position=1)]
    [Alias('file_path')]
    [string]$FilePath,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('optional_hosts','OptionalHostIds')]
    [string[]]$OptionalHostId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:post',Position=3)]
    [ValidateRange(1,600)]
    [int32]$Timeout,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:post',Position=4)]
    [ValidateRange(1,600)]
    [Alias('host_timeout_duration')]
    [int32]$HostTimeout,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('batch_id')]
    [string]$BatchId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-get-command/v1:post')]
    [switch]$Wait
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($OptionalHostId) { @($OptionalHostId).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['OptionalHostId'] = @($List) }
    if ($PSBoundParameters.HostTimeout) {
      # Add 's' to denote seconds for 'host_timeout_duration'
      $PSBoundParameters.HostTimeout = [string]::Concat($PSBoundParameters.HostTimeout,'s')
    }
    foreach ($Request in (Invoke-Falcon @Param -UserInput $PSBoundParameters)) {
      if ($Request.batch_get_cmd_req_id -and $Request.combined.resources) {
        # Output result with 'batch_get_cmd_req_id' and 'hosts' values
        $Request = [PSCustomObject]@{
          batch_get_cmd_req_id = $Request.batch_get_cmd_req_id
          hosts = @($Request.combined.resources.PSObject.Properties.Value).foreach{
            # Append 'batch_get_cmd_req_id'
            Set-Property $_ batch_get_cmd_req_id $Request.batch_get_cmd_req_id
            $_
          }
        }
        @($Request.hosts).Where({$_.errors}).foreach{
          # Write warning for hosts in batch that produced errors
          $PSCmdlet.WriteWarning(('[Invoke-FalconBatchGet]',($_.errors.code,
            $_.errors.message -join ': '),('[aid: {0}]' -f $_.aid) -join ' '))
        }
        @($Request.hosts).Where({$_.stderr}).foreach{
          # Write warning for hosts in batch that produced 'stderr'
          $PSCmdlet.WriteWarning(('[Invoke-FalconBatchGet]',$_.stderr,
            ('[aid: {0}' -f $_.aid) -join ' '))
        }
      }
      if ($Wait) { Wait-RtrGet $Request $MyInvocation.MyCommand.Name } else { $Request }
    }
  }
}
function Invoke-FalconCommand {
<#
.SYNOPSIS
Issue a Real-time Response read-only command to an existing single-host or batch session
.DESCRIPTION
Sessions can be started using 'Start-FalconSession'. A successfully created session will contain a 'session_id'
or 'batch_id' value which can be used with the '-SessionId' or '-BatchId' parameters.

The 'Wait' parameter will use 'Confirm-FalconCommand' to check for command results every 20 seconds until complete
or processing ends.

Requires 'Real time response: Read'.
.PARAMETER Command
Real-time Response command
.PARAMETER Argument
Arguments to include with the command
.PARAMETER OptionalHostId
Restrict execution to specific host identifiers
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 30]
.PARAMETER HostTimeout
Length of time to wait for a result from target host(s), in seconds
.PARAMETER SessionId
Session identifier
.PARAMETER BatchId
Batch session identifier
.PARAMETER Wait
Use 'Confirm-FalconCommand' to retrieve command result
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconCommand
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/combined/batch-command/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/command/v1:post',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-command/v1:post',Mandatory,Position=1)]
    [ValidateSet('cat','cd','clear','csrutil','env','eventlog backup','eventlog export','eventlog list',
      'eventlog view','filehash','getsid','help','history','ifconfig','ipconfig','ls','mount','netstat',
      'ps','reg query','users',IgnoreCase=$false)]
    [Alias('base_command')]
    [string]$Command,
    [Parameter(ParameterSetName='/real-time-response/entities/command/v1:post',Position=2)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-command/v1:post',Position=2)]
    [Alias('Arguments')]
    [string]$Argument,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-command/v1:post',Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('optional_hosts','OptionalHostIds')]
    [string[]]$OptionalHostId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-command/v1:post',Position=4)]
    [ValidateRange(1,600)]
    [int32]$Timeout,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-command/v1:post',Position=5)]
    [ValidateRange(1,600)]
    [Alias('host_timeout_duration')]
    [int32]$HostTimeout,
    [Parameter(ParameterSetName='/real-time-response/entities/command/v1:post',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$SessionId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-command/v1:post',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('batch_id')]
    [string]$BatchId,
    [Parameter(ParameterSetName='/real-time-response/entities/command/v1:post')]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-command/v1:post')]
    [switch]$Wait
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($OptionalHostId) { @($OptionalHostId).foreach{ $List.Add($_) }}}
  end {
    # Verify 'Endpoint' using BatchId/SessionId
    $Endpoint = if ($PSBoundParameters.BatchId) {
      if ($List) { $PSBoundParameters['OptionalHostId'] = @($List) }
      '/real-time-response/combined/batch-command/v1:post'
    } else {
      '/real-time-response/entities/command/v1:post'
    }
    if ($Endpoint) {
      if ($PSBoundParameters.HostTimeout) {
        # Add 's' to denote seconds for 'host_timeout_duration'
        $PSBoundParameters.HostTimeout = [string]::Concat($PSBoundParameters.HostTimeout,'s')
      }
      $PSBoundParameters['command_string'] = if ($PSBoundParameters.Argument) {
        # Join 'Command' and 'Argument' into 'command_string'
        @($PSBoundParameters.Command,$PSBoundParameters.Argument) -join ' '
        [void]$PSBoundParameters.Remove('Argument')
      } else {
        $PSBoundParameters.Command
      }
      foreach ($Request in (Invoke-Falcon @Param -Endpoint $Endpoint -UserInput $PSBoundParameters)) {
        if ($BatchId -and @($Request.PSObject.Properties.Value).Where({$_.session_id})) {
          $Request = @($Request.PSObject.Properties.Value).Where({$_.session_id}).foreach{
            # Append 'batch_id' to command results with a 'session_id'
            Set-Property $_ batch_id $BatchId
            $_
          }
        }
        if ($Wait -and $SessionId) {
          Wait-RtrCommand $Request $MyInvocation.MyCommand.Name
        } else {
          $Request
        }
      }
    }
  }
}
function Invoke-FalconResponderCommand {
<#
.SYNOPSIS
Issue a Real-time Response active-responder command to an existing single-host or batch session
.DESCRIPTION
Sessions can be started using 'Start-FalconSession'. A successfully created session will contain a 'session_id'
or 'batch_id' value which can be used with the '-SessionId' or '-BatchId' parameters.

The 'Wait' parameter will use 'Confirm-FalconResponderCommand' or 'Confirm-FalconGetFile' to check for command
results every 20 seconds until complete or processing ends.

Requires 'Real time response: Write'.
.PARAMETER Command
Real-time Response command
.PARAMETER Argument
Arguments to include with the command
.PARAMETER OptionalHostId
Restrict execution to specific host identifiers
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 30]
.PARAMETER HostTimeout
Length of time to wait for a result from target host(s), in seconds
.PARAMETER SessionId
Session identifier
.PARAMETER BatchId
Batch session identifier
.PARAMETER Wait
Use 'Confirm-FalconResponderCommand' or 'Confirm-FalconGetFile' to retrieve command result
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconResponderCommand
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/active-responder-command/v1:post',Mandatory,
      Position=1)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post',
      Mandatory,Position=1)]
    [ValidateSet('cat','cd','clear','cp','csrutil','encrypt','env','eventlog backup','eventlog export',
      'eventlog list','eventlog view','filehash','get','getsid','help','history','ifconfig','ipconfig','kill','ls',
      'map','memdump','mkdir','mount','mv','netstat','ps','reg delete','reg load','reg query','reg set',
      'reg unload','restart','rm','runscript','shutdown','tar','umount','unmap','update history','update install',
      'update list','update query','users','xmemdump','zip',IgnoreCase=$false)]
    [Alias('base_command')]
    [string]$Command,
    [Parameter(ParameterSetName='/real-time-response/entities/active-responder-command/v1:post',Position=2)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post',
       Position=2)]
    [Alias('Arguments')]
    [string]$Argument,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post',
      Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('optional_hosts','OptionalHostIds')]
    [string[]]$OptionalHostId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post',
       Position=4)]
    [ValidateRange(1,600)]
    [int32]$Timeout,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post',
       Position=5)]
    [ValidateRange(1,600)]
    [Alias('host_timeout_duration')]
    [int32]$HostTimeout,
    [Parameter(ParameterSetName='/real-time-response/entities/active-responder-command/v1:post',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$SessionId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post',
      Mandatory,ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('batch_id')]
    [string]$BatchId,
    [Parameter(ParameterSetName='/real-time-response/entities/active-responder-command/v1:post')]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-active-responder-command/v1:post')]
    [switch]$Wait
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name }
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
      if ($List) { $GetParam['OptionalHostId'] = @($List) }
      Invoke-FalconBatchGet @GetParam
    } else {
      # Verify 'Endpoint' using BatchId/SessionId
      $Endpoint = if ($PSBoundParameters.BatchId) {
        if ($List) { $PSBoundParameters['OptionalHostId'] = @($List) }
        '/real-time-response/combined/batch-active-responder-command/v1:post'
      } elseif ($PSBoundParameters.SessionId) {
        '/real-time-response/entities/active-responder-command/v1:post'
      }
      if ($Endpoint) {
        if ($PSBoundParameters.HostTimeout) {
          # Add 's' to denote seconds for 'host_timeout_duration'
          $PSBoundParameters.HostTimeout = [string]::Concat($PSBoundParameters.HostTimeout,'s')
        }
        $PSBoundParameters['command_string'] = if ($PSBoundParameters.Argument) {
          # Join 'Command' and 'Argument' into 'command_string'
          @($PSBoundParameters.Command,$PSBoundParameters.Argument) -join ' '
          [void]$PSBoundParameters.Remove('Argument')
        } else {
          $PSBoundParameters.Command
        }
        foreach ($Request in (Invoke-Falcon @Param -Endpoint $Endpoint -UserInput $PSBoundParameters)) {
          if ($BatchId -and @($Request.PSObject.Properties.Value).Where({$_.session_id})) {
            $Request = @($Request.PSObject.Properties.Value).Where({$_.session_id}).foreach{
              # Append 'batch_id' to command results with a 'session_id'
              Set-Property $_ batch_id $BatchId
              $_
            }
          }
          if ($Wait -and $Command -eq 'get') {
            Wait-RtrGet $Request $MyInvocation.MyCommand.Name
          } elseif ($Wait -and $SessionId) {
            Wait-RtrCommand $Request $MyInvocation.MyCommand.Name
          } else {
            $Request
          }
        }
      }
    }
  }
}
function Receive-FalconGetFile {
<#
.SYNOPSIS
Download a password protected .7z archive containing a Real-time Response 'get' file [password: 'infected']
.DESCRIPTION
'Sha256' and 'SessionId' values can be found using 'Confirm-FalconGetFile'. 'Invoke-FalconResponderCommand' or
'Invoke-FalconAdminCommand' can be used to issue a 'get' command to a single-host, and 'Invoke-FalconBatchGet' can
be used for multiple hosts within existing Real-time Response session.

Requires 'Real time response: Write'.
.PARAMETER Path
Destination path
.PARAMETER Sha256
Sha256 hash value
.PARAMETER SessionId
Session identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconGetFile
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/extracted-file-contents/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/extracted-file-contents/v1:get',Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/real-time-response/entities/extracted-file-contents/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$Sha256,
    [Parameter(ParameterSetName='/real-time-response/entities/extracted-file-contents/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$SessionId,
    [Parameter(ParameterSetName='/real-time-response/entities/extracted-file-contents/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/x-7z-compressed' }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
    if (!$PSBoundParameters.Path) {
      # When 'Path' is not specified, use 'sha256' from a 'Confirm-FalconGetFile' result
      $PSBoundParameters['Path'] = Join-Path (Get-Location).Path $PSBoundParameters.Sha256
    }
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path '7z'
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } elseif ($PSBoundParameters.SessionId -and $PSBoundParameters.Sha256) {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Receive-FalconPutFile {
<#
.SYNOPSIS
Download a Real-time Response 'put' file
.DESCRIPTION
Requires 'Real time response: Write'.
.PARAMETER Path
Destination path
.PARAMETER Id
'Put' file identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconPutFile
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/put-file-contents/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/put-file-contents/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('name')]
    [string]$Path,
    [Parameter(ParameterSetName='/real-time-response/entities/put-file-contents/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/real-time-response/entities/put-file-contents/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream' }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconCommand {
<#
.SYNOPSIS
Remove a command from a queued Real-time Response session
.DESCRIPTION
Requires 'Real time response: Read'.
.PARAMETER SessionId
Session identifier
.PARAMETER CloudRequestId
Cloud request identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCommand
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/queued-sessions/command/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/queued-sessions/command/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$SessionId,
    [Parameter(ParameterSetName='/real-time-response/entities/queued-sessions/command/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('cloud_request_id','task_id')]
    [string]$CloudRequestId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconGetFile {
<#
.SYNOPSIS
Remove Real-time Response 'get' files
.DESCRIPTION
Delete files previously retrieved during a Real-time Response session. The required 'Id' and 'SessionId' values
are contained in the results of 'Start-FalconSession' and 'Invoke-FalconAdminCommand' or 'Invoke-FalconBatchGet'
commands.

Requires 'Real time response: Write'.
.PARAMETER SessionId
Session identifier
.PARAMETER Id
Real-time Response 'get' file identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconGetFile
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/file/v2:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/file/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$SessionId,
    [Parameter(ParameterSetName='/real-time-response/entities/file/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconPutFile {
<#
.SYNOPSIS
Remove a Real-time Response 'put' file
.DESCRIPTION
Requires 'Real time response (admin): Write'.
.PARAMETER Id
Real-time Response 'put' file identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconPutFile
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/put-files/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/put-files/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconScript {
<#
.SYNOPSIS
Remove a custom Real-time Response script
.DESCRIPTION
Requires 'Real time response (admin): Write'.
.PARAMETER Id
Script identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconScript
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/scripts/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/scripts/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconSession {
<#
.SYNOPSIS
Remove a Real-time Response session
.DESCRIPTION
Requires 'Real time response: Read'.
.PARAMETER Id
Session identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconSession
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/sessions/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/sessions/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('session_id')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconPutFile {
<#
.SYNOPSIS
Upload a Real-time Response 'put' file
.DESCRIPTION
Requires 'Real time response (admin): Write'.
.PARAMETER Name
File name
.PARAMETER Description
File description
.PARAMETER Comment
Comment for audit log
.PARAMETER Path
Path to local file
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconPutFile
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/put-files/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/put-files/v1:post',
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidateLength(1,32766)]
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
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconScript {
<#
.SYNOPSIS
Upload a custom Real-time Response script
.DESCRIPTION
Requires 'Real time response (admin): Write'.
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
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconScript
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
    [ValidateLength(1,32766)]
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
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Start-FalconSession {
<#
.SYNOPSIS
Initialize a single-host or batch Real-time Response session
.DESCRIPTION
Real-time Response sessions require Host identifier values. Sessions that are successfully started return a
'session_id' (for single hosts) or 'batch_id' (multiple hosts) value which can be used to issue commands that
will be processed by the host(s) in the session.

Commands can be issued using 'Invoke-FalconCommand', 'Invoke-FalconResponderCommand', 'Invoke-FalconAdminCommand'
and 'Invoke-FalconBatchGet'.

Requires 'Real time response: Read'.
.PARAMETER QueueOffline
Add non-responsive hosts to the offline queue
.PARAMETER ExistingBatchId
Add hosts to an existing batch session
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 30]
.PARAMETER HostTimeout
Length of time to wait for a result from target host(s), in seconds
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Start-FalconSession
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/combined/batch-init-session/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/sessions/v1:post',Position=1)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-init-session/v1:post',Position=1)]
    [Alias('queue_offline')]
    [boolean]$QueueOffline,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-init-session/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('existing_batch_id')]
    [string]$ExistingBatchId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-init-session/v1:post',Position=3)]
    [Parameter(ParameterSetName='/real-time-response/entities/sessions/v1:post',Position=2)]
    [ValidateRange(1,600)]
    [int32]$Timeout,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-init-session/v1:post',Position=4)]
    [ValidateRange(1,600)]
    [Alias('host_timeout_duration')]
    [int32]$HostTimeout,
    [Parameter(ParameterSetName='/real-time-response/entities/sessions/v1:post',Mandatory)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-init-session/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [ValidateLength(1,10000)]
    [Alias('host_ids','device_id','device_ids','aid','HostId','HostIds')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      # Verify 'Endpoint' using BatchId/SessionId and select hosts
      [void]$PSBoundParameters.Remove('Id')
      $Endpoint = if ($List.Count -eq 1 -and !$HostTimeout -and !$ExistingBatchId) {
        $PSBoundParameters['device_id'] = @($List)[0]
        '/real-time-response/entities/sessions/v1:post'
      } else {
        if ($PSBoundParameters.HostTimeout) {
          # Add 's' to denote seconds for 'host_timeout_duration'
          $PSBoundParameters.HostTimeout = [string]::Concat($PSBoundParameters.HostTimeout,'s')
        }
        $PSBoundParameters['host_ids'] = @($List)
        '/real-time-response/combined/batch-init-session/v1:post'
      }
      @(Invoke-Falcon @Param -Endpoint $Endpoint -UserInput $PSBoundParameters).foreach{
        if ($_.batch_id -and $_.resources) {
          [string]$BatchId = $_.batch_id
          @($_.resources.PSObject.Properties.Value).Where({$_.errors}).foreach{
            # Write warning for hosts in batch that produced errors
            $PSCmdlet.WriteWarning("[Start-FalconSession] $(
              @($_.errors.code,$_.errors.message) -join ': ') [aid: $($_.aid)]")
          }
          @($_.resources.PSObject.Properties.Value).Where({$_.session_id}).foreach{
            # Append 'batch_id' for hosts with a 'session_id'
            Set-Property $_ batch_id $BatchId
          }
          [PSCustomObject]@{
            batch_id = $_.batch_id
            hosts = $_.resources.PSObject.Properties.Value
          }
        } else {
          # Append 'aid' to single host session result
          Set-Property $_ aid $List[0]
          $_
        }
      }
    }
  }
}
function Update-FalconSession {
<#
.SYNOPSIS
Refresh a single-host or batch Real-time Response session to prevent expiration
.DESCRIPTION
Real-time Response sessions expire after 5 minutes by default. Any commands that were issued to a session that
take longer than 5 minutes will not return results without refreshing the session to keep it alive until the
command process completes.

Requires 'Real time response: Read'.
.PARAMETER QueueOffline
Add non-responsive hosts to the offline queue
.PARAMETER HostToRemove
Host identifier(s) to remove from a batch Real-time Response session
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 30]
.PARAMETER HostId
Host identifier, for a single-host session
.PARAMETER BatchId
Batch session identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconSession
#>
  [CmdletBinding(DefaultParameterSetName='/real-time-response/entities/refresh-session/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/real-time-response/entities/refresh-session/v1:post',Position=1)]
    [Parameter(ParameterSetName='/real-time-response/combined/batch-refresh-session/v1:post',Position=1)]
    [Alias('queue_offline')]
    [boolean]$QueueOffline,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-refresh-session/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('hosts_to_remove','HostsToRemove')]
    [string[]]$HostToRemove,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-refresh-session/v1:post',Position=3)]
    [ValidateRange(1,600)]
    [int32]$Timeout,
    [Parameter(ParameterSetName='/real-time-response/entities/refresh-session/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('device_id','host_ids','aid')]
    [string]$HostId,
    [Parameter(ParameterSetName='/real-time-response/combined/batch-refresh-session/v1:post',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('batch_id')]
    [string]$BatchId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($HostToRemove) { @($HostToRemove).foreach{ $List.Add($_) }}}
  end {
    # Verify 'Endpoint' using HostId/BatchId
    [string]$Endpoint = if ($PSBoundParameters.HostId) {
      '/real-time-response/entities/refresh-session/v1:post'
    } elseif ($PSBoundParameters.BatchId) {
      if ($List) { $PSBoundParameters['HostToRemove'] = @($List) }
      '/real-time-response/combined/batch-refresh-session/v1:post'
    }
    @(Invoke-Falcon @Param -Endpoint $Endpoint -UserInput $PSBoundParameters).foreach{
      if ($Endpoint -eq '/real-time-response/combined/batch-refresh-session/v1:post') {
        @($_.PSObject.Properties.Value).Where({$_.errors}).foreach{
          # Write warning for hosts in batch that produced errors
          $PSCmdlet.WriteWarning("[Update-FalconSession] $(
            @($_.errors.code,$_.errors.message) -join ': ') [aid: $($_.aid)]")
        }
        # Output 'batch_id' and 'hosts' containing result
        [PSCustomObject]@{
          batch_id = $BatchId
          hosts = $_.PSObject.Properties.Value
        }
      } else {
        # Append 'aid' to single host session result
        Set-Property $_ aid $HostId
        $_
      }
    }
  }
}