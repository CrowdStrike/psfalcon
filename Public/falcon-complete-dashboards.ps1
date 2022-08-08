function Get-FalconCompleteAllowlist {
<#
.SYNOPSIS
Search for Falcon Complete Allowlist tickets
.DESCRIPTION
Requires 'Falcon Complete Dashboards: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Dashboards
#>
    [CmdletBinding(DefaultParameterSetName='/falcon-complete-dashboards/queries/allowlist/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/allowlist/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/allowlist/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/allowlist/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/allowlist/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/allowlist/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/allowlist/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconCompleteBlocklist {
<#
.SYNOPSIS
Search for Falcon Complete Blocklist tickets
.DESCRIPTION
Requires 'Falcon Complete Dashboards: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Dashboards
#>
    [CmdletBinding(DefaultParameterSetName='/falcon-complete-dashboards/queries/blocklist/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/blocklist/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/blocklist/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/blocklist/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/blocklist/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/blocklist/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/blocklist/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconCompleteCollection {
<#
.SYNOPSIS
Search for Falcon Complete device collections
.DESCRIPTION
Requires 'Falcon Complete Dashboards: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Dashboards
#>
    [CmdletBinding(DefaultParameterSetName='/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
           Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
           Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/devicecount-collections/v1:get',
           Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/devicecount-collections/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconCompleteDetection {
<#
.SYNOPSIS
Search for Falcon Complete detections
.DESCRIPTION
Requires 'Falcon Complete Dashboards: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Dashboards
#>
    [CmdletBinding(DefaultParameterSetName='/falcon-complete-dashboards/queries/detects/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/detects/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/detects/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/detects/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/detects/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/detects/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/detects/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconCompleteEscalation {
<#
.SYNOPSIS
Search for Falcon Complete escalations
.DESCRIPTION
Requires 'Falcon Complete Dashboards: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Dashboards
#>
    [CmdletBinding(DefaultParameterSetName='/falcon-complete-dashboards/queries/escalations/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/escalations/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/escalations/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/escalations/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/escalations/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/escalations/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/escalations/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconCompleteIncident {
<#
.SYNOPSIS
Search for Falcon Complete incidents
.DESCRIPTION
Requires 'Falcon Complete Dashboards: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Dashboards
#>
    [CmdletBinding(DefaultParameterSetName='/falcon-complete-dashboards/queries/incidents/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/incidents/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/incidents/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/incidents/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/incidents/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/incidents/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/incidents/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconCompleteRemediation {
<#
.SYNOPSIS
Search for Falcon Complete remediations
.DESCRIPTION
Requires 'Falcon Complete Dashboards: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Falcon-Complete-Dashboards
#>
    [CmdletBinding(DefaultParameterSetName='/falcon-complete-dashboards/queries/remediations/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/remediations/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/remediations/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/remediations/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/remediations/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/remediations/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/falcon-complete-dashboards/queries/remediations/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}