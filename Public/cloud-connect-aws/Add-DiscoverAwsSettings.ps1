function Add-DiscoverAwsSettings {
    <#
    .SYNOPSIS
        Create or update global settings applied to all provisioned AWS accounts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-aws/CreateOrUpdateAWSSettings')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-aws/CreateOrUpdateAWSSettings')
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