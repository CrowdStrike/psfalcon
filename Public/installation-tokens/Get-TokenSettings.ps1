function Get-TokenSettings {
    <#
    .SYNOPSIS
        Check current installation token settings
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'installation-tokens/customer-settings-read')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('installation-tokens/customer-settings-read')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Endpoint -Endpoint $Endpoints[0]
        }
    }
}