function Edit-Detection {
<#
.SYNOPSIS
    Modify the state, assignee, and visibility of detections
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'UpdateDetectsByIdsV2')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('UpdateDetectsByIdsV2')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if ($Dynamic.Comment.Value -and (-not($Dynamic.AssignedToUuid.Value -or $Dynamic.ShowInUi.Value -or
            $Dynamic.Status.Value))) {
            throw 'Must define AssignedToUuid, ShowInUi or Status when adding a Comment'
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