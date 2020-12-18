function Revoke-Token {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'oauth2/oauth2RevokeToken')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('oauth2/oauth2RevokeToken')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            if (-not $Falcon.Token) {
                throw "No token available to be revoked"
            }
            $Param = @{
                Endpoint = $Endpoints[0]
                Body     = "token=$($Falcon.token -replace 'bearer ', '')"
            }
            $Request = Invoke-Endpoint @Param
            if ($Request.meta) {
                Clear-Auth
            }
            $Request
        }
    }
}