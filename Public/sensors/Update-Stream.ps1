function Update-Stream {
    <#
    .SYNOPSIS
        Discover event streams
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'sensors/refreshActiveStreamSession')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('sensors/refreshActiveStreamSession')
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