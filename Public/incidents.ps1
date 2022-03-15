function Get-FalconBehavior {
    [CmdletBinding(DefaultParameterSetName = '/incidents/queries/behaviors/v1:get')]
    param(
        [Parameter(ParameterSetName = '/incidents/entities/behaviors/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^ind:\w{32}:(\d|\-)+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 2)]
        [ValidateSet('timestamp.asc', 'timestamp.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/incidents/queries/behaviors/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
                Body  = @{ root = @('ids') }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconIncident {
    [CmdletBinding(DefaultParameterSetName = '/incidents/queries/incidents/v1:get')]
    param(
        [Parameter(ParameterSetName = '/incidents/entities/incidents/GET/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 2)]
        [ValidateSet('assigned_to.asc', 'assigned_to.desc', 'assigned_to_name.asc', 'assigned_to_name.desc',
            'end.asc', 'end.desc', 'modified_timestamp.asc', 'modified_timestamp.desc', 'name.asc', 'name.desc',
            'sort_score.asc', 'sort_score.desc', 'start.asc', 'start.desc', 'state.asc', 'state.desc',
            'status.asc', 'status.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/incidents/queries/incidents/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
                Body  = @{ root = @('ids') }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconScore {
    [CmdletBinding(DefaultParameterSetName = '/incidents/combined/crowdscores/v1:get')]
    param(
        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 2)]
        [ValidateSet('score.asc', 'score.desc', 'timestamp.asc', 'timestamp.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 3)]
        [ValidateRange(1,2500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/incidents/combined/crowdscores/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{ Query = @('sort', 'offset', 'filter', 'limit') }
        }
        Invoke-Falcon @Param
    }
}
function Invoke-FalconIncidentAction {
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
        $Fields = @{
            OverwriteDetects = 'overwrite_detects'
            UpdateDetects    = 'update_detects'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('update_detects', 'overwrite_detects')
                Body  = @{
                    root              = @('ids')
                    action_parameters = @('name', 'value')
                }
            }
        }
        if ($Param.Inputs.Name -ne 'update_status') {
            Invoke-Falcon @Param
        } elseif ($Param.Inputs.Name -eq 'update_status' -and $Param.Inputs.Value -match
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