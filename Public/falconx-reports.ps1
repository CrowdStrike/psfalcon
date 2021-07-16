function Get-FalconIntel {
<#
.Synopsis
Search for intelligence reports
.Parameter Ids
Intelligence report identifier(s)
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
falconx-reports:read
#>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/reports/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/reports/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/intel/entities/reports/v1:get', Position = 6)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 6)]
        [array] $Fields,

        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/intel/entities/reports/v1:get')]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/intel/entities/reports/v1:get')]
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
function Receive-FalconIntel {
<#
.Synopsis
Download an intelligence report
.Parameter Id
Intelligence report identifier
.Parameter Path
Destination path
.Role
falconx-reports:read
#>
    [CmdletBinding(DefaultParameterSetName = '/intel/entities/report-files/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/report-files/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{2,}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/intel/entities/report-files/v1:get', Mandatory = $true, Position = 2)]
        [ValidatePattern('\.pdf$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/pdf'
            }
            Format   = @{
                Query   = @('id')
                Outfile = 'path'
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}