function Get-AwsAccount {
    <#
    .SYNOPSIS
        Search for provisioned AWS accounts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-aws/QueryAWSAccountsForIDs')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-aws/QueryAWSAccountsForIDs', 'cloud-connect-aws/QueryAWSAccounts')

        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('cloud-connect-aws/QueryAWSAccounts')
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
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
            Invoke-Request @Param
        }
    }
}
