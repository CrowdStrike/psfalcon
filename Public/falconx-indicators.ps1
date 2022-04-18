function Get-FalconIndicator {
<#
.SYNOPSIS
Search for intelligence indicators
.DESCRIPTION
Requires 'Indicators (Falcon X): Read'.
.PARAMETER Id
Indicator identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER IncludeDeleted
Include previously deleted indicators
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/queries/indicators/v1:get')]
    param(
        [Parameter(ParameterSetName='/intel/entities/indicators/GET/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=1)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=3)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=3)]
        [ValidateSet('id|asc','id|desc','indicator|asc','indicator|desc','type|asc','type|desc',
            'published_date|asc','published_date|desc','last_updated|asc','last_updated|desc',
            '_marker|asc','_marker|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=4)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=5)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=5)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=6)]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=6)]
        [Alias('include_deleted')]
        [boolean]$IncludeDeleted,
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/indicators/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('sort','limit','filter','offset','include_deleted','q')
                Body = @{ root = @('ids') }
            }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}