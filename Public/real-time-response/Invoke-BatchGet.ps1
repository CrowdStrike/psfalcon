function Invoke-BatchGet {
    <#
    .SYNOPSIS
        Issue a 'get' command to a batch session
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'real-time-response/BatchGetCmd')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('real-time-response/BatchGetCmd')
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