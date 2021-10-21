function Get-FalconCompleteAllowlist {
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteBlocklist {
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteCollection {
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
            Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
            Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
            Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
            Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteDetection {
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteEscalation {
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteIncident {
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteRemediation {
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}