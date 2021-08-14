function Get-FalconActor {
<#
.Synopsis
Search for threat actors
.Parameter Ids
Threat actor identifier(s)
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
.Parameter Fields
Specific fields, or a predefined collection name surrounded by two underscores [default: __basic__]
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconx-actors:read
.Example
PS>Get-FalconActor -Filter "target_countries:'united states'+target_countries:'canada'+target_industries:
'government'" -Detailed

Return the first set of detailed results for actors that have targeted government in the United States and Canada.
.Example
PS>Get-FalconActor -Ids <id>, <id>

List information about actors <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/actors/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/actors/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/intel/queries/actors/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/intel/queries/actors/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/intel/queries/actors/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get', Position = 3)]
        [ValidateSet('name|asc', 'name|desc', 'target_countries|asc', 'target_countries|desc',
            'target_industries|asc', 'target_industries|desc', 'type|asc', 'type|desc', 'created_date|asc',
            'created_date|desc', 'last_activity_date|asc', 'last_activity_date|desc', 'last_modified_date|asc',
            'last_modified_date|desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/intel/queries/actors/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/intel/queries/actors/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/intel/entities/actors/v1:get', Position = 6)]
        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get', Position = 6)]
        [array] $Fields,

        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/intel/queries/actors/v1:get')]
        [Parameter(ParameterSetName = '/intel/combined/actors/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/intel/queries/actors/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Query = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('sort', 'limit', 'ids', 'filter', 'offset', 'fields', 'q')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}