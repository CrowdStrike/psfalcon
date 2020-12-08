function Invoke-IncidentAction {
    <#
    .SYNOPSIS
        Perform actions on Incidents
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'incidents/PerformIncidentAction')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('incidents/PerformIncidentAction')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            if ($Dynamic.ActionName.value -eq 'update_status') {
                if ($Dynamic.ActionValue.value -match '(closed|in_progress|new|reopened)') {
                    $Dynamic.ActionValue.value = switch ($Dynamic.ActionValue.value) {
                        'new' { "20" }
                        'reopened' { "25" }
                        'in_progress' { "30" }
                        'closed' { "40" }
                    }
                }
            }
            else {
                throw "Valid values for 'update_status': 'closed', 'in_progress', 'new', 'reopened'."
            }
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
