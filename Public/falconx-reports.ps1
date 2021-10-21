function Get-FalconIntel {
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/reports/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/reports/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/intel/queries/reports/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/intel/combined/reports/v1:get', Position = 3)]
        [ValidateSet('name|asc', 'name|desc', 'target_countries|asc', 'target_countries|desc',
            'target_industries|asc', 'target_industries|desc', 'type|asc', 'type|desc', 'created_date|asc',
            'created_date|desc', 'last_modified_date|asc', 'last_modified_date|desc')]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('sort', 'limit', 'ids', 'filter', 'offset', 'fields', 'q')
            }
        }
        Invoke-Falcon @Param
    }
}
function Receive-FalconIntel {
    [CmdletBinding(DefaultParameterSetName = '/intel/entities/report-files/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/report-files/v1:get', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
    process {
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
        Invoke-Falcon @Param
    }
}