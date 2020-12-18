function Edit-Detection {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'detects/UpdateDetectsByIdsV2')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('detects/UpdateDetectsByIdsV2')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif ($PSBoundParameters.Comment -and (-not($PSBoundParameters.AssignedUuid -or
        $PSBoundParameters.ShowInUi -or $PSBoundParameters.Status))) {
            throw 'AssignedUuid, ShowInUi or Status are required when using Comment'
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}