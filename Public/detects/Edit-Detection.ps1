function Edit-Detection {
<#
.SYNOPSIS
    Modify the state, assignee, and visibility of detections
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'detects/UpdateDetectsByIdsV2')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('detects/UpdateDetectsByIdsV2')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } elseif ($PSBoundParameters.Comment -and (-not($PSBoundParameters.AssignedUuid -or
        $PSBoundParameters.ShowInUi -or $PSBoundParameters.Status))) {
            # Output exception if 'comment' is provided without other required field
            throw 'Must provide AssignedUuid, ShowInUi or Status when adding a Comment'
        } else {
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}