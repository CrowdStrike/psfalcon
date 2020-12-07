function Get-HorizonSchedule {
    <#
    .SYNOPSIS
        Retrieve the Falcon Horizon scan schedule
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'settings/GetCSPMScanSchedule')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('settings/GetCSPMScanSchedule')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}