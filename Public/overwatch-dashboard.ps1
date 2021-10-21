function Get-FalconOverWatchEvent {
    [CmdletBinding(DefaultParameterSetName = '/overwatch-dashboards/aggregates/ow-events-global-counts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/overwatch-dashboards/aggregates/ow-events-global-counts/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconOverWatchDetection {
    [CmdletBinding(DefaultParameterSetName = '/overwatch-dashboards/aggregates/detections-global-counts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/overwatch-dashboards/aggregates/detections-global-counts/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconOverWatchIncident {
    [CmdletBinding(DefaultParameterSetName = '/overwatch-dashboards/aggregates/incidents-global-counts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/overwatch-dashboards/aggregates/incidents-global-counts/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter')
            }
        }
        Invoke-Falcon @Param
    }
}