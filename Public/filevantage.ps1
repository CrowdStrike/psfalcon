function Get-FalconFimChange {
    [CmdletBinding(DefaultParameterSetName = '/filevantage/queries/changes/v2:get')]
    param(
        [Parameter(ParameterSetName = '/filevantage/entities/changes/v2:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/filevantage/queries/changes/v2:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/filevantage/queries/changes/v2:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/filevantage/queries/changes/v2:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/filevantage/queries/changes/v2:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/filevantage/queries/changes/v2:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/filevantage/queries/changes/v2:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/filevantage/queries/changes/v2:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('filter', 'sort', 'limit', 'offset', 'ids')
            }
        }
        Invoke-Falcon @Param
    }
}