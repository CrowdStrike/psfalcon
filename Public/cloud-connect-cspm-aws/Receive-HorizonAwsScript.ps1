function Receive-HorizonAwsScript {
    <#
    .SYNOPSIS
        Download a script to provide Horizon with access to your AWS account
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-cspm-aws/GetCSPMAwsAccountScriptsAttachment')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-cspm-aws/GetCSPMAwsAccountScriptsAttachment')
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