function Get-FirewallPlatform {
<#
.SYNOPSIS
    Search for firewall platforms
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'query-platforms')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'query-platforms',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('query-platforms', 'get-platforms')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
                Entity = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'Detailed' {
                    $Param['Detailed'] = 'PlatformIds'
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}
