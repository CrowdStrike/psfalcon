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
        # Endpoint(s) used by function
        $Endpoints = @('oauth2/oauth2RevokeToken')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if (-not $Falcon.Token) {
                # Output exception if a token is not present
                throw "No token available to be revoked"
            }
            # Base request parameters
            $Param = @{
                Endpoint = $Endpoints[0]
                Body = "token=$($Falcon.token -replace 'bearer ', '')"
            }
            # Make request
            $Request = Invoke-Endpoint @Param

            if ($Request.meta) {
                # Clear cached token and credential information
                @('id', 'secret', 'CID', 'token').foreach{
                    if ($Falcon.$_) {
                        $Falcon.$_ = $null
                        Write-Debug "[$($MyInvocation.MyCommand.Name)] cleared $_"
                    }
                }
                $Falcon.Expires = Get-Date
            }
            # Output result
            $Request
        }
    }
}