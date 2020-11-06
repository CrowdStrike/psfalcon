function New-AzureAccount {
    <#
    .SYNOPSIS
        Creates a new Azure account and generates a script to grant access to the Falcon platform
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-azure/CreateCSPMAzureAccount')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-azure/CreateCSPMAzureAccount')
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