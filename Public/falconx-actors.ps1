function Get-FalconActor {
<#
.SYNOPSIS
Search for threat actors
.DESCRIPTION
Requires 'Actors (Falcon X): Read'.
.PARAMETER Id
Threat actor identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Fields
Specific fields, or a predefined collection name surrounded by two underscores [default: _basic_]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/queries/actors/v1:get')]
    param(
        [Parameter(ParameterSetName='/intel/entities/actors/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=1)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=3)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=3)]
        [ValidateSet('name|asc','name|desc','target_countries|asc','target_countries|desc',
            'target_industries|asc','target_industries|desc','type|asc','type|desc','created_date|asc',
            'created_date|desc','last_activity_date|asc','last_activity_date|desc','last_modified_date|asc',
            'last_modified_date|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=4)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/intel/entities/actors/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=5)]
        [string[]]$Fields,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/actors/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','limit','ids','filter','offset','fields','q') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}