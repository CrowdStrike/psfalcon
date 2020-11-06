function Revoke-Token {
    <#
.SYNOPSIS
    Revoke your current OAuth2 access token before the end of its standard lifespan
.LINK
    https://github.com/CrowdStrike/psfalcon
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
                @('id', 'secret', 'CID', 'token').foreach{
                    if ($Falcon.$_) {
                        $Falcon.$_ = $null
                        Write-Debug "[$($MyInvocation.MyCommand.Name)] cleared $_"
                    }
                }
                $Falcon.Expires = Get-Date
            }
            $Request
        }
    }
}