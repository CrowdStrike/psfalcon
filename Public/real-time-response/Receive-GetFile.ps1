function Receive-GetFile {
    <#
    .SYNOPSIS
        Download a file extracted through a Real-time Response 'get' request in an encrypted .7z archive
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'real-time-response/RTR-GetExtractedFileContents')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('real-time-response/RTR-GetExtractedFileContents')
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