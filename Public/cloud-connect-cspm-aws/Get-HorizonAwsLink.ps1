function Get-HorizonAwsLink {
    <#
    .SYNOPSIS
        Return a URL to visit within your AWS environment to provide Horizon access
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-cspm-aws/GetCSPMAwsConsoleSetupURLs')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-cspm-aws/GetCSPMAwsConsoleSetupURLs')
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