function Edit-HorizonAzureAccount {
    <#
    .SYNOPSIS
        Change the Client ID for an Azure Account in Horizon
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-cspm-azure/UpdateCSPMAzureAccountClientID')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-cspm-azure/UpdateCSPMAzureAccountClientID')
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