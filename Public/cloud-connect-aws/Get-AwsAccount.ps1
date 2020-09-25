function Get-AwsAccount {
<#
.SYNOPSIS
    Search for provisioned AWS accounts
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'QueryAWSAccountsForIDs')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'QueryAWSAccountsForIDs',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'QueryAWSAccountsForIDs',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QueryAWSAccountsForIDs', 'QueryAWSAccounts')

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
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = 'Combined'
                    $Param.Query = $Endpoints[1]
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}
