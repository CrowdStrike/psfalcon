﻿function New-AwsAccount {
    <#
    .SYNOPSIS
        Provision AWS accounts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-aws/ProvisionAWSAccounts')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-aws/ProvisionAWSAccounts')
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