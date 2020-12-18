function New-HorizonAzureAccount {
    <#
    .SYNOPSIS
        Create a Horizon Azure account and generate a script to grant access
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-cspm-azure/CreateCSPMAzureAccount')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-cspm-azure/CreateCSPMAzureAccount')
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