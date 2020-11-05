function Remove-AwsAccount {
    <#
    .SYNOPSIS
        Delete AWS Accounts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-aws/DeleteAWSAccounts')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-aws/DeleteAWSAccounts')

        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}