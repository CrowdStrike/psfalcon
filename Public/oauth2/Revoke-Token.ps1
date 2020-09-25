function Revoke-Token {
<#
.SYNOPSIS
    Revoke your current OAuth2 access token before the end of its standard lifespan
.DESCRIPTION
    Additional information is available with the -Help parameter
#>
    [CmdletBinding()]
    [OutputType()]
    param()
    begin {
        # Endpoint(s) used by function
        $Endpoints = @('oauth2RevokeToken')
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Base request parameters
            $Param = @{
                Endpoint = $Endpoints[0]
                Body = "token=$((Get-SecureString $Falcon.token) -replace 'bearer ', '')"
            }
            # Make request
            $Request = Invoke-Endpoint @Param

            if ($Request.meta) {
                # Clear cached token and credential information
                @('id', 'secret', 'CID', 'token').foreach{
                    # Clear cached authentication information
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