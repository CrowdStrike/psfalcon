function Get-FalconIndicator {
<#
.Synopsis
Search for intelligence indicators
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Query
Perform a generic substring search across available fields
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter IncludeDeleted
Include previously deleted indicators
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconx-indicators:read
#>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/indicators/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/indicators/GET/v1:post', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 6)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 6)]
        [boolean] $IncludeDeleted,

        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get')]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            IncludeDeleted = 'include_deleted'
            Query          = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('sort', 'limit', 'filter', 'offset', 'include_deleted', 'q')
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