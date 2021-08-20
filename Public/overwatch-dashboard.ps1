function Get-FalconOverWatchEvent {
    [CmdletBinding(DefaultParameterSetName = '/overwatch-dashboards/aggregates/ow-events-global-counts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/overwatch-dashboards/aggregates/ow-events-global-counts/v1:get',
            Mandatory = $true, Position = 1)]
        [string] $Filter
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconOverWatchDetection {
    [CmdletBinding(DefaultParameterSetName = '/overwatch-dashboards/aggregates/detections-global-counts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/overwatch-dashboards/aggregates/detections-global-counts/v1:get',
            Mandatory = $true, Position = 1)]
        [string] $Filter
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconOverWatchIncident {
    [CmdletBinding(DefaultParameterSetName = '/overwatch-dashboards/aggregates/incidents-global-counts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/overwatch-dashboards/aggregates/incidents-global-counts/v1:get',
            Mandatory = $true, Position = 1)]
        [string] $Filter
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}