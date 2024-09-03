function Get-FalconFoundryRepository {
<#
.SYNOPSIS
List available Falcon Foundry repositories
.DESCRIPTION
Requires 'App Logs: Read'.
.PARAMETER CheckTestData
Include whether test data is present in the application repository
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFoundryRepository
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/combined/repos/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/combined/repos/v1:get',Position=1)]
    [Alias('check_test_data')]
    [boolean]$CheckTestData
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconFoundrySearch {
<#
.SYNOPSIS
Get the results of a saved search
.DESCRIPTION
Requires 'App Logs: Read'.
.PARAMETER Id
Search identifier
.PARAMETER AppId
Foundry application identifier
.PARAMETER InferJsonTypes
Whether to try to infer data types in json event response instead of returning map[string]string
.PARAMETER Limit
Maximum number of results per request
.PARAMETER MatchResponseSchema
Whether to validate search results against their schema
.PARAMETER Metadata
Whether to include metadata in the response
.PARAMETER Offset
Position to begin retrieving results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFoundrySearch
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',Mandatory,Position=0)]
    [Alias('job_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',Position=0)]
    [Alias('app_id')]
    [string]$AppId,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',Position=0)]
    [Alias('infer_json_types')]
    [boolean]$InferJsonTypes,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',Position=0)]
    [string]$Limit,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',Position=0)]
    [Alias('match_response_schema')]
    [boolean]$MatchResponseSchema,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',Position=0)]
    [boolean]$Metadata,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get')]
    [string]$Offset
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconFoundryView {
<#
.SYNOPSIS
List available Falcon Foundry views
.DESCRIPTION
Requires 'App Logs: Read'.
.PARAMETER CheckTestData
Include whether test data is present in the application repository
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFoundryView
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/views/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/views/v1:get',Position=1)]
    [Alias('check_test_data')]
    [boolean]$CheckTestData
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}