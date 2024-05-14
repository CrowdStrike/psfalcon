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
function New-CommandName {
<#
.SYNOPSIS
Asynchronously ingest data into the application repository
.DESCRIPTION
Requires 'App Logs: Write'.
.PARAMETER DataFile
Data file to ingest
.PARAMETER Repo
Repository name if not part of a foundry app
.PARAMETER Tag
Custom tag for ingested data in the form tag:value
.PARAMETER TagSource
Tag the data with the specified source
.PARAMETER TestData
Tag the data with test-ingest
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/data-ingestion/ingest-async/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest-async/v1:post',Mandatory,Position=0)]
    [Alias('data_file')]
    [file]$DataFile,
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest-async/v1:post',Position=0)]
    [string]$Repo,
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest-async/v1:post',Position=0)]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest-async/v1:post',Position=0)]
    [Alias('tag_source')]
    [string]$TagSource,
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest-async/v1:post',Position=0)]
    [Alias('test_data')]
    [boolean]$TestData
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Synchronously ingest data into the application repository
.DESCRIPTION
Requires 'App Logs: Write'.
.PARAMETER DataFile
Data file to ingest
.PARAMETER Tag
Custom tag for ingested data in the form tag:value
.PARAMETER TagSource
Tag the data with the specified source
.PARAMETER TestData
Tag the data with test-ingest
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/data-ingestion/ingest/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest/v1:post',Mandatory,Position=0)]
    [Alias('data_file')]
    [file]$DataFile,
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest/v1:post',Position=0)]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest/v1:post',Position=0)]
    [Alias('tag_source')]
    [string]$TagSource,
    [Parameter(ParameterSetName='/loggingapi/entities/data-ingestion/ingest/v1:post',Position=0)]
    [Alias('test_data')]
    [boolean]$TestData
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Execute a dynamic saved search
.DESCRIPTION
Requires 'App Logs: Write'.
.PARAMETER AppId
Application ID.
.PARAMETER IncludeSchemaGeneration
Include generated schemas in the response
.PARAMETER IncludeTestData
Include test data when executing searches
.PARAMETER InferJsonTypes
Whether to try to infer data types in json event response instead of returning map[string]string
.PARAMETER MatchResponseSchema
Whether to validate search results against their schema
.PARAMETER Metadata
Whether to include metadata in the response
.PARAMETER Mode
Mode to execute the query under.
.PARAMETER End

.PARAMETER RepoOrView

.PARAMETER SearchQuery

.PARAMETER SearchQueryArgs

.PARAMETER Start

.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('app_id')]
    [string]$AppId,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('include_schema_generation')]
    [boolean]$IncludeSchemaGeneration,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('include_test_data')]
    [boolean]$IncludeTestData,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('infer_json_types')]
    [boolean]$InferJsonTypes,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('match_response_schema')]
    [boolean]$MatchResponseSchema,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [boolean]$Metadata,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [ValidateSet('sync','async',IgnoreCase=$false)]
    [string]$Mode,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [string]$End,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('repo_or_view')]
    [string]$RepoOrView,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('search_query')]
    [string]$SearchQuery,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [Alias('search_query_args')]
    [object]$SearchQueryArgs,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute-dynamic/v1:post',Position=0)]
    [string]$Start
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Get the results of a saved search
.DESCRIPTION
Requires 'App Logs: Read'.
.PARAMETER JobId
Job ID for a previously executed async query
.PARAMETER AppId
Application ID.
.PARAMETER InferJsonTypes
Whether to try to infer data types in json event response instead of returning map[string]string
.PARAMETER Limit
Maximum number of results per request

Maximum number of records to return.
.PARAMETER MatchResponseSchema
Whether to validate search results against their schema
.PARAMETER Metadata
Whether to include metadata in the response
.PARAMETER Offset
Position to begin retrieving results

Starting pagination offset of records to return.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:get',Mandatory,Position=0)]
    [Alias('job_id')]
    [string]$JobId,
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
function New-CommandName {
<#
.SYNOPSIS
Execute a saved search
.DESCRIPTION
Requires 'App Logs: Write'.
.PARAMETER AppId
Application ID.
.PARAMETER Detailed
Whether to include search field details
.PARAMETER IncludeTestData
Include test data when executing searches
.PARAMETER InferJsonTypes
Whether to try to infer data types in json event response instead of returning map[string]string
.PARAMETER MatchResponseSchema
Whether to validate search results against their schema
.PARAMETER Metadata
Whether to include metadata in the response
.PARAMETER Extrarename

.PARAMETER Extrasearch

.PARAMETER Extrasort

.PARAMETER Extrawhere

.PARAMETER Parameters

.PARAMETER End

.PARAMETER FqlStatements

.PARAMETER Id
XXX identifier
.PARAMETER Mode

.PARAMETER Name

.PARAMETER Start

.PARAMETER Version

.PARAMETER WithIn

.PARAMETER WithLimit

.PARAMETER As

.PARAMETER Field

.PARAMETER WithSort

.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('app_id')]
    [string]$AppId,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [boolean]$Detailed,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('include_test_data')]
    [boolean]$IncludeTestData,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('infer_json_types')]
    [boolean]$InferJsonTypes,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('match_response_schema')]
    [boolean]$MatchResponseSchema,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [boolean]$Metadata,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Mandatory,Position=0)]
    [string]$Extrarename,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Mandatory,Position=0)]
    [string]$Extrasearch,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Mandatory,Position=0)]
    [string]$Extrasort,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Mandatory,Position=0)]
    [string]$Extrawhere,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Mandatory,Position=0)]
    [object]$Parameters,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [string]$End,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('fql_statements')]
    [object]$FqlStatements,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [string]$Id,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [string]$Mode,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [string]$Name,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [string]$Start,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [string]$Version,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('with_in')]
    [object]$WithIn,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('with_limit')]
    [object]$WithLimit,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Mandatory,Position=0)]
    [string]$As,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Mandatory,Position=0)]
    [string]$Field,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/execute/v1:post',Position=0)]
    [Alias('with_sort')]
    [object]$WithSort
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Populate a saved search
.DESCRIPTION
Requires 'App Logs: Write'.
.PARAMETER AppId
Application ID.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/saved-searches/ingest/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/ingest/v1:post',Position=0)]
    [Alias('app_id')]
    [string]$AppId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Get the results of a saved search as a file
.DESCRIPTION
Requires 'App Logs: Read'.
.PARAMETER JobId
Job ID for a previously executed async query
.PARAMETER InferJsonTypes
Whether to try to infer data types in json event response instead of returning map[string]string
.PARAMETER ResultFormat
Result Format
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/loggingapi/entities/saved-searches/job-results-download/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/job-results-download/v1:get',Mandatory,Position=0)]
    [Alias('job_id')]
    [string]$JobId,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/job-results-download/v1:get',Position=0)]
    [Alias('infer_json_types')]
    [boolean]$InferJsonTypes,
    [Parameter(ParameterSetName='/loggingapi/entities/saved-searches/job-results-download/v1:get',Position=0)]
    [ValidateSet('json','csv',IgnoreCase=$false)]
    [Alias('result_format')]
    [string]$ResultFormat
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}