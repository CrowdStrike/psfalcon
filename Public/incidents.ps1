function Get-FalconBehavior {
<#
.SYNOPSIS
Search for behaviors
.DESCRIPTION
Requires 'Incidents: Read'.
.PARAMETER Id
Behavior identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Incident-and-Detection-Monitoring
#>
    [CmdletBinding(DefaultParameterSetName='/incidents/queries/behaviors/v1:get')]
    param(
        [Parameter(ParameterSetName='/incidents/entities/behaviors/GET/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^ind:\w{32}:(\d|\-)+$')]
        [Alias('ids','behavior_id')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get',Position=2)]
        [ValidateSet('timestamp.asc','timestamp.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get',Position=4)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('sort','offset','filter','limit')
                Body = @{ root = @('ids') }
            }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconIncident {
<#
.SYNOPSIS
Search for incidents
.DESCRIPTION
Requires 'Incidents: Read'.
.PARAMETER Id
Incident identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Incident-and-Detection-Monitoring
#>
    [CmdletBinding(DefaultParameterSetName='/incidents/queries/incidents/v1:get')]
    param(
        [Parameter(ParameterSetName='/incidents/entities/incidents/GET/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [Alias('ids','incident_id')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get',Position=2)]
        [ValidateSet('assigned_to.asc','assigned_to.desc','assigned_to_name.asc','assigned_to_name.desc',
            'end.asc','end.desc','modified_timestamp.asc','modified_timestamp.desc','name.asc','name.desc',
            'sort_score.asc','sort_score.desc','start.asc','start.desc','state.asc','state.desc',
            'status.asc','status.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get',Position=4)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('sort','offset','filter','limit')
                Body = @{ root = @('ids') }
            }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconScore {
<#
.SYNOPSIS
Search for CrowdScore values
.DESCRIPTION
Requires 'Incidents: Read'.
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
https://github.com/CrowdStrike/psfalcon/wiki/Incident-and-Detection-Monitoring
#>
    [CmdletBinding(DefaultParameterSetName='/incidents/combined/crowdscores/v1:get')]
    param(
        [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get',Position=2)]
        [ValidateSet('score.asc','score.desc','timestamp.asc','timestamp.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get',Position=3)]
        [ValidateRange(1,2500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get',Position=4)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get')]
        [switch]$Total
    )
    process {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','limit') }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Invoke-FalconIncidentAction {
<#
.SYNOPSIS
Perform actions on incidents
.DESCRIPTION
Requires 'Incidents: Write'.
.PARAMETER Name
Action to perform
.PARAMETER Value
Value for the chosen action
.PARAMETER UpdateDetects
Update status of related 'new' detections
.PARAMETER OverwriteDetects
Replace existing status for related detections
.PARAMETER Id
Incident identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Incident-and-Detection-Monitoring
#>
    [CmdletBinding(DefaultParameterSetName='/incidents/entities/incident-actions/v1:post')]
    param(
        [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Mandatory,Position=1)]
        [ValidateSet('add_tag','delete_tag','update_description','update_name','update_status',
            IgnoreCase=$false)]
        [string]$Name,
        [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Mandatory,Position=2)]
        [string]$Value,
        [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Position=3)]
        [Alias('update_detects')]
        [boolean]$UpdateDetects,
        [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Position=4)]
        [Alias('overwrite_detects')]
        [boolean]$OverwriteDetects,
        [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=5)]
        [ValidatePattern('^inc:\w{32}:\w{32}$')]
        [Alias('ids','incident_id')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('update_detects','overwrite_detects')
                Body = @{
                    root = @('ids')
                    action_parameters = @('name','value')
                }
            }
            Max = 1000
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process { if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}}
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            if ($PSBoundParameters.Name -eq 'update_status') {
                if ($PSBoundParameters.Value -notmatch '^(closed|in_progress|new|reopened)$') {
                    throw "Valid values for 'update_status': 'closed', 'in_progress', 'new', 'reopened'."
                } else {
                    $PSBoundParameters['Value'] = switch ($PSBoundParameters.Value) {
                        'new'         { '20' }
                        'reopened'    { '25' }
                        'in_progress' { '30' }
                        'closed'      { '40' }
                    }
                }
            }
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}