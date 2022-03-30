function Get-FalconIntel {
<#
.SYNOPSIS
Search for intelligence reports
.DESCRIPTION
Requires 'Reports (Falcon X): Read'.
.PARAMETER Id
Report identifier
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
.PARAMETER Fields
Specific fields,or a predefined collection name surrounded by two underscores [default: _basic_]
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/queries/reports/v1:get')]
    param(
        [Parameter(ParameterSetName='/intel/entities/reports/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=1)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=2)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,

        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=3)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=3)]
        [ValidateSet('name|asc','name|desc','target_countries|asc','target_countries|desc',
            'target_industries|asc','target_industries|desc','type|asc','type|desc','created_date|asc',
            'created_date|desc','last_modified_date|asc','last_modified_date|desc',IgnoreCase=$false)]
        [string]$Sort,

        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=4)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=5)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=5)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/intel/entities/reports/v1:get',Position=6)]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=6)]
        [string[]]$Fields,

        [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Mandatory)]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/intel/entities/reports/v1:get')]
        [Parameter(ParameterSetName='/intel/combined/reports/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/intel/entities/reports/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','limit','ids','filter','offset','fields','q') }
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
function Receive-FalconIntel {
<#
.SYNOPSIS
Download an intelligence report
.DESCRIPTION
Requires 'Reports (Falcon X): Read'.
.PARAMETER Path
Destination path [default: <slug>.pdf]
.PARAMETER Id
Report identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Intel
#>
    [CmdletBinding(DefaultParameterSetName='/intel/entities/report-files/v1:get')]
    param(
        [Parameter(ParameterSetName='/intel/entities/report-files/v1:get',ValueFromPipelineByPropertyName,
            Position=1)]
        [Alias('slug')]
        [string]$Path,

        [Parameter(ParameterSetName='/intel/entities/report-files/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{2,}$')]
        [string]$Id,

        [Parameter(ParameterSetName='/intel/entities/report-files/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/pdf' }
            Format = @{
                Query = @('id')
                Outfile = 'path'
            }
        }
    }
    process {
        $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'pdf'
        $OutPath = Test-OutFile $PSBoundParameters.Path
        if ($OutPath.Category -eq 'ObjectNotFound') {
            Write-Error @OutPath
        } elseif ($PSBoundParameters.Path) {
            if ($OutPath.Category -eq 'WriteError' -and !$Force) {
                Write-Error @OutPath
            } else {
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}