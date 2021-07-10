function Get-FalconBehavior {
<#
.Synopsis
Search for behaviors
.Parameter Ids
One or more behavior identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
incidents:read
#>
    [CmdletBinding(DefaultParameterSetName = '/incidents/queries/behaviors/v1:get')]
    param(
        [Parameter(ParameterSetName = '/incidents/entities/behaviors/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^ind:\w{32}:\d+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 2)]
        [ValidateSet('timestamp.asc', 'timestamp.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
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
function Get-FalconIncident {
<#
.Synopsis
Search for incidents
.Parameter Ids
One or more incident identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
incidents:read
#>
    [CmdletBinding(DefaultParameterSetName = '/incidents/queries/incidents/v1:get')]
    param(
        [Parameter(ParameterSetName = '/incidents/entities/incidents/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 2)]
        [ValidateSet('assigned_to.asc', 'assigned_to.desc', 'assigned_to_name.asc', 'assigned_to_name.desc',
            'end.asc', 'end.desc', 'modified_timestamp.asc', 'modified_timestamp.desc', 'name.asc', 'name.desc',
            'sort_score.asc', 'sort_score.desc', 'start.asc', 'start.desc', 'state.asc', 'state.desc',
            'status.asc', 'status.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/json'
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
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
function Get-FalconScore {
<#
.Synopsis
Search for CrowdScore values
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
incidents:read
#>
    [CmdletBinding(DefaultParameterSetName = '/incidents/combined/crowdscores/v1:get')]
    param(
        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 2)]
        [ValidateSet('score.asc', 'score.desc', 'timestamp.asc', 'timestamp.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/json'
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
function Invoke-FalconIncidentAction {
<#
.Synopsis
Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident
name or description
.Parameter Name
Action to perform
.Parameter Value
Value for the chosen action
.Parameter Ids
One or more incident identifiers
.Parameter UpdateDetects
Update status of related 'new' detections
.Parameter OverwriteDetects
Replace existing status for related detections
.Role
incidents:write
#>
    [CmdletBinding(DefaultParameterSetName = '/incidents/entities/incident-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/incidents/entities/incident-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add_tag', 'delete_tag', 'update_description', 'update_name', 'update_status')]
        [string] $Name,

        [Parameter(ParameterSetName = '/incidents/entities/incident-actions/v1:post', Mandatory = $true,
            Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/incidents/entities/incident-actions/v1:post', Mandatory = $true,
            Position = 3)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/incidents/entities/incident-actions/v1:post', Position = 4)]
        [boolean] $UpdateDetects,

        [Parameter(ParameterSetName = '/incidents/entities/incident-actions/v1:post', Position = 5)]
        [boolean] $OverwriteDetects
    )
    begin {
        @('OverwriteDetects', 'UpdateDetects').foreach{
            if ($PSBoundParameters.$_) {
                # Rename parameter for API submission
                $Field = switch ($_) {
                    'OverwriteDetects' { 'overwrite_detects' }
                    'UpdateDetects'    { 'update_detects' }
                }
                $PSBoundParameters.Add($Field, $PSBoundParameters.$_)
                [void] $PSBoundParameters.Remove($_)
            }
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('update_detects', 'overwrite_detects')
                Body  = @{
                    root = @('ids')
                    action_parameters = @('name', 'value')
                }
            }
        }
    }
    process {
        if ($Param.Inputs.Name -eq 'update_status' -and $Param.Inputs.Value -match
        '^(closed|in_progress|new|reopened)$') {
            $Param.Inputs.Value = switch ($Param.Inputs.Value) {
                'new'         { '20' }
                'reopened'    { '25' }
                'in_progress' { '30' }
                'closed'      { '40' }
            }
            Invoke-Falcon @Param
        } else {
            throw "Valid values for 'update_status': 'closed', 'in_progress', 'new', 'reopened'."
        }
    }
}
