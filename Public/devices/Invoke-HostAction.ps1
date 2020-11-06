function Invoke-HostAction {
    <#
    .SYNOPSIS
        Perform actions on Hosts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'devices/PerformActionV2')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('devices/PerformActionV2')
        return (Get-Dictionary $Endpoints[0] -OutVariable Dynamic)
    }
    begin {
        $Max = if ($Dynamic.ActionName.value -match '(hide_host|unhide_host)') {
            100
        }
        else {
            500
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            foreach ($Param in (Get-Param $Endpoints[0] $Dynamic $Max)) {
                Format-Param -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
