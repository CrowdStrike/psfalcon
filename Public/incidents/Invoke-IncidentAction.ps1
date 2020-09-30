function Invoke-IncidentAction {
<#
.SYNOPSIS
    Perform actions on Incidents
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'PerformIncidentAction')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('PerformIncidentAction')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ($Dynamic.ActionName.value -eq 'update_status') {
                if ($Dynamic.ActionValue.value -match '(closed|in_progress|new|reopened)') {
                    $Dynamic.ActionValue.value = switch ($Dynamic.ActionValue.value) {
                        # Convert update_status value to integer string
                        'new' { "20" }
                        'reopened' { "25" }
                        'in_progress' { "30" }
                        'closed' { "40" }
                    }
                } else {
                    # Output exception
                    throw "Valid values for 'update_status': 'closed', 'in_progress', 'new', 'reopened'."
                }
            }
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
