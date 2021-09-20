function Get-FalconQuarantine {
    [CmdletBinding(DefaultParameterSetName = '/quarantine/queries/quarantined-files/v1:get')]
    param(
        [Parameter(ParameterSetName = '/quarantine/entities/quarantined-files/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{64}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get', Position = 3)]
        [ValidateSet('hostname.asc', 'hostname.desc', 'username.asc', 'username.desc', 'date_updated.asc',
            'date_updated.desc', 'date_created.asc', 'date_created.desc', 'paths.path.asc', 'paths.path.desc',
            'paths.state.asc', 'paths.state.desc', 'state.asc', 'state.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:get')]
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
                Query = @('sort', 'limit', 'filter', 'offset', 'q')
                Body  = @{
                    root = @('ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconQuarantineAction {
    [CmdletBinding(DefaultParameterSetName = '/quarantine/entities/quarantined-files/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/quarantine/entities/quarantined-files/v1:patch', Mandatory = $true,
            Position = 1)]
        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidateSet('release', 'unrelease', 'delete')]
        [string] $Action,

        [Parameter(ParameterSetName = '/quarantine/entities/quarantined-files/v1:patch', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}_\w{64}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:patch', Mandatory = $true,
            Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:patch', Position = 3)]
        [string] $Query,

        [Parameter(ParameterSetName = '/quarantine/entities/quarantined-files/v1:patch', Position = 3)]
        [Parameter(ParameterSetName = '/quarantine/queries/quarantined-files/v1:patch', Position = 4)]
        [string] $Comment
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
                Body  = @{
                    root = @('action', 'filter', 'ids', 'comment', 'q')
                }
            }
            Max      = 500
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Test-FalconQuarantineAction {
    [CmdletBinding(DefaultParameterSetName = '/quarantine/aggregates/action-update-count/v1:get')]
    param(
        [Parameter(ParameterSetName = '/quarantine/aggregates/action-update-count/v1:get', Mandatory = $true,
            Position = 1)]
        [string] $Filter
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}