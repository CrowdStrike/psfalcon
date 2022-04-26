function Get-FalconFimChange {
<#
.SYNOPSIS
Search for Falcon FileVantage changes
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER Id
Activity identifier
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
https://github.com/crowdstrike/psfalcon/wiki/FileVantage
#>
    [CmdletBinding(DefaultParameterSetName='/filevantage/queries/changes/v2:get')]
    param(
        [Parameter(ParameterSetName='/filevantage/entities/changes/v2:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/filevantage/queries/changes/v2:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/filevantage/queries/changes/v2:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/filevantage/queries/changes/v2:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/filevantage/queries/changes/v2:get',Position=5)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/filevantage/queries/changes/v2:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/filevantage/queries/changes/v2:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/filevantage/queries/changes/v2:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('filter','sort','limit','offset','ids') }
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