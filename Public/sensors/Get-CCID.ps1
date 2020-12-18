function Get-CCID {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'sensors/GetSensorInstallersCCIDByQuery')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('sensors/GetSensorInstallersCCIDByQuery')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Endpoint -Endpoint $Endpoints[0]
        }
    }
}