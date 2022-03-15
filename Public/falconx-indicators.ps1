function Get-FalconIndicator {
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/indicators/v1:get')]
    param(
        [Parameter(ParameterSetName = '/intel/entities/indicators/GET/v1:post', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/intel/queries/indicators/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/intel/combined/indicators/v1:get', Position = 3)]
        [ValidateSet('id|asc', 'id|desc', 'indicator|asc', 'indicator|desc', 'type|asc', 'type|desc',
            'published_date|asc', 'published_date|desc', 'last_updated|asc', 'last_updated|desc',
            '_marker|asc', '_marker|desc')]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('sort', 'limit', 'filter', 'offset', 'include_deleted', 'q')
                Body  = @{ root = @('ids') }
            }
        }
        Invoke-Falcon @Param
    }
}