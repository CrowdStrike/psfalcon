function Get-FalconRemediation {
    [CmdletBinding(DefaultParameterSetName = '/spotlight/entities/remediations/v2:get')]
    param(
        [Parameter(ParameterSetName = '/spotlight/entities/remediations/v2:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconVulnerability {
    [CmdletBinding(DefaultParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
    param(
        [Parameter(ParameterSetName = '/spotlight/entities/vulnerabilities/v2:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Mandatory = $true,
            Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 3)]
        [ValidateRange(1, 400)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 4)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 5)]
        [string] $After,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('after', 'sort', 'ids', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}