function Get-FalconCompleteAllowlist {
<#
.Synopsis
Search for Falcon Complete Allowlist tickets
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
.Example
PS>Get-FalconCompleteAllowlist

Return the first set of identifiers for Falcon Complete Allowlist tickets.
.Example
PS>Get-FalconCompleteAllowlist -Total

Return the total number of Falcon Complete Allowlist tickets.
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
        [int] $Offset,

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
Search for Falcon Complete Blocklist tickets
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
.Example
PS>Get-FalconCompleteBlocklist

Return the first set of identifiers for Falcon Complete Blocklist tickets.
.Example
PS>Get-FalconCompleteBlocklist -Total

Return the total number of Falcon Complete Blocklist tickets.
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
        [int] $Offset,

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
Search for Falcon Complete device collections
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
.Example
PS>Get-FalconCompleteCollection

Return the first set of identifiers for Falcon Complete device collections.
.Example
PS>Get-FalconCompleteCollection -Total

Return the total number of Falcon Complete device collections.
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
        [int] $Offset,

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
Search for Falcon Complete detections
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
.Example
PS>Get-FalconCompleteDetection

Return the first set of identifiers for Falcon Complete detections.
.Example
PS>Get-FalconCompleteDetection -Total

Return the total number of Falcon Complete detections.
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
        [int] $Offset,

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
Search for Falcon Complete escalations
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
.Example
PS>Get-FalconCompleteEscalation

Return the first set of identifiers for Falcon Complete escalations.
.Example
PS>Get-FalconCompleteEscalation -Total

Return the total number of Falcon Complete escalations.
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
        [int] $Offset,

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
Search for Falcon Complete incidents
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
.Example
PS>Get-FalconCompleteIncident

Return the first set of identifiers for Falcon Complete incidents.
.Example
PS>Get-FalconCompleteIncident -Total

Return the total number of Falcon Complete incidents.
#>
    [CmdletBinding(DefaultParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get')]
    param(
        [Parameter(ParameterSetName = '/falcon-complete-dashboards/queries/incidents/v1:get', Position = 1)]
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
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
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
Search for Falcon Complete remediations
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
.Example
PS>Get-FalconCompleteRemediation

Return the first set of identifiers for Falcon Complete remediations.
.Example
PS>Get-FalconCompleteRemediation -Total

Return the total number of Falcon Complete remediations.
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
        [int] $Offset,

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
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}