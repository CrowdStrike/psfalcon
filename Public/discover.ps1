function Get-FalconAsset {
<#
.SYNOPSIS
Search for assets in Falcon Discover
.DESCRIPTION
Requires 'Falcon Discover: Read'.
.PARAMETER Id
Asset identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Discover
#>
    [CmdletBinding(DefaultParameterSetName='/discover/queries/hosts/v1:get')]
    param(
        [Parameter(ParameterSetName='/discover/entities/hosts/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}_\w+$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=3)]
        [ValidateRange(1,100)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=4)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('filter','sort','limit','offset','ids') }
            Max = 100
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