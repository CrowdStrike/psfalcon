function Get-FalconOverWatchEvent {
<#
.Synopsis
Get the total number of OverWatch events across all customers
.Parameter Filter
Falcon Query Language expression to limit results
.Role
overwatch-dashboard:read
#>
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
<#
.Synopsis
Get the total number of detections pushed across all customers
.Parameter Filter
Falcon Query Language expression to limit results
.Role
overwatch-dashboard:read
#>
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
<#
.Synopsis
Get the total number of incidents pushed across all customers
.Parameter Filter
Falcon Query Language expression to limit results
.Role
overwatch-dashboard:read
#>
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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}