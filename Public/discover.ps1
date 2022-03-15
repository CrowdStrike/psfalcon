function Get-FalconAsset {
    [CmdletBinding(DefaultParameterSetName = '/discover/queries/hosts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/discover/entities/hosts/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}_\w+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 3)]
        [ValidateRange(1,100)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{ Query = @('filter', 'q', 'sort', 'limit', 'offset', 'ids') }
            Max      = 100
        }
        Invoke-Falcon @Param
    }
}