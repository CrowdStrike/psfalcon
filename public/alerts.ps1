function Get-FalconAlert {
<#
.SYNOPSIS
Search for alerts
.DESCRIPTION
Requires 'Alerts: Read'.
.PARAMETER Id
Alert identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconAlert
#>
    [CmdletBinding(DefaultParameterSetName='/alerts/queries/alerts/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/alerts/entities/alerts/v1:post',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}:(aggind|ind):[a-fA-F0-9]{32}:.+$')]
        [Alias('Ids','composite_id')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get',Position=4)]
        [ValidateRange(1,10000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/alerts/queries/alerts/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('ids') }
                Query = @('filter','q','sort','limit','offset')
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
}
function Invoke-FalconAlertAction {
<#
.SYNOPSIS
Perform actions on alerts
.DESCRIPTION
Requires 'Alerts: Write'.
.PARAMETER Name
Action to perform
.PARAMETER Value
Value for the chosen action
.PARAMETER Id
Alert identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconAlertAction
#>
    [CmdletBinding(DefaultParameterSetName='/alerts/entities/alerts/v2:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/alerts/entities/alerts/v2:patch',Mandatory,Position=1)]
        [ValidateSet('add_tag','append_comment','assign_to_name','assign_to_user_id','assign_to_uuid',
            'new_behavior_processed','remove_tag','remove_tags_by_prefix','show_in_ui','update_status',
            'unassign',IgnoreCase=$false)]
        [string]$Name,
        [Parameter(ParameterSetName='/alerts/entities/alerts/v2:patch',Position=2)]
        [string]$Value,
        [Parameter(ParameterSetName='/alerts/entities/alerts/v2:patch',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline,Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}:(aggind|ind):[a-fA-F0-9]{32}:.+$')]
        [Alias('Ids','composite_id')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('ids','action_parameters') }}
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            [hashtable]$Parameters = @{ name = $PSBoundParameters.name }
            if ($PSBoundParameters.Value) { $Parameters['value'] = $PSBoundParameters.Value }
            $PSBoundParameters['action_parameters'] = @($Parameters)
            @('Name','Value').foreach{ [void]$PSBoundParameters.Remove($_) }
            Invoke-Falcon @Param -UserInput $PSBoundParameters
        }
    }
}