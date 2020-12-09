function Get-IOCTotal {
    <#
    .SYNOPSIS
        Retrieve the total number of hosts that have observed a custom IOC
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'indicators/DevicesCount')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('indicators/DevicesCount')
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