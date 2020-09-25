function Invoke-IncidentAction {
<#
.SYNOPSIS
    Perform actions on Incidents
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'PerformIncidentAction')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('PerformIncidentAction')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if ($Dynamic.ActionName.value -eq 'update_status') {
            if ($Dynamic.ActionValue.value -match '(closed|in_progress|new|reopened)') {
                $Dynamic.ActionValue.value = switch ($Dynamic.ActionValue.value) {
                    # Convert update_status value to integer
                    'new' {
                        "20"
                    }
                    'reopened' {
                        "25"
                    }
                    'in_progress' {
                        "30"
                    }
                    'closed' {
                        "40"
                    }
                }
            } else {
                throw "Valid values for 'update_status': 'closed', 'in_progress', 'new', 'reopened'."
            }
        }
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
