function Get-FalconCompleteAllowlist {
<#
.Synopsis
Retrieve allowlist tickets that match the provided filter criteria
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconcomplete-dashboard:read
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/allowlist/v1:get')]
        [switch] $Total
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
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteBlocklist {
<#
.Synopsis
Retrieve blocklist tickets that match the provided filter criteria
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconcomplete-dashboard:read
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/blocklist/v1:get')]
        [switch] $Total
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
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteCollection {
<#
.Synopsis
Retrieve device count collection Ids that match the provided FQL filter criteria
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconcomplete-dashboard:read
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
            Position = 1)]
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
        [string] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
        [switch] $Total
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
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteDetection {
<#
.Synopsis
Retrieve DetectionsIds that match the provided FQL filter
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconcomplete-dashboard:read
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/detects/v1:get')]
        [switch] $Total
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
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteEscalation {
<#
.Synopsis
Retrieve escalation tickets that match the provided filter criteria
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconcomplete-dashboard:read
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/escalations/v1:get')]
        [switch] $Total
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
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteIncident {
<#
.Synopsis
Retrieve incidents that match the provided filter criteria
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconcomplete-dashboard:read
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get')]
        [switch] $Total
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
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCompleteRemediation {
<#
.Synopsis
Retrieve remediation tickets that match the provided filter criteria
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
falconcomplete-dashboard:read
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/remediations/v1:get')]
        [switch] $Total
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
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}