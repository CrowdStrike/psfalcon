function Edit-InstallToken {
    <#
    .SYNOPSIS
        Update one or more installation tokens
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'installation-tokens/tokens-update')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('installation-tokens/tokens-update')
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