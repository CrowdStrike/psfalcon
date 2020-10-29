function Request-Token {
<#
.SYNOPSIS
    Generate an OAuth2 access token
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'oauth2/oauth2AccessToken')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('oauth2/oauth2AccessToken')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ($PSBoundParameters.Cloud) {
                # Set hostname
                $Falcon.Hostname = switch ($PSBoundParameters.Cloud) {
                    'eu-1' { 'https://api.eu-1.crowdstrike.com' }
                    'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com' }
                    'us-1' { 'https://api.crowdstrike.com' }
                    'us-2' { 'https://api.us-2.crowdstrike.com' }
                }
                Write-Debug "[$($MyInvocation.MyCommand.Name)] hostname: $($Falcon.Hostname)"
            }
            if (-not($Dynamic.Id.Value)) {
                if ($Falcon.Id) {
                    # Collect saved Id
                    $Dynamic.Id.Value = $Falcon.Id
                } else {
                    # Force input of Id
                    $Dynamic.Id.Value = Read-Host "Id"
                }
            }
            if (-not($Dynamic.Secret.Value)) {
                if ($Falcon.Secret) {
                    # Collect saved Secret
                    $Dynamic.Secret.Value = $Falcon.Secret
                } else {
                    # Force input of Secret
                    $Dynamic.Secret.Value = Read-Host "Secret"
                }
            }
            Write-Debug "[$($MyInvocation.MyCommand.Name)] id: $($Dynamic.Id.Value)"

            if ((-not($Dynamic.CID.Value)) -and $Falcon.CID) {
                # Collect saved CID
                $Dynamic.CID.Value = $Falcon.CID
            }
            # Base parameters
            $Param = @{
                Endpoint = $Endpoints[0]
                Body = "client_id=$($Dynamic.Id.Value)&client_secret=$($Dynamic.Secret.Value)"
            }
            if ($Dynamic.CID.Value) {
                $Param.Body += "&member_cid=$($Dynamic.CID.Value)"

                Write-Debug "[$($MyInvocation.MyCommand.Name)] cid: $($Dynamic.CID.Value)"
            }
            # Make request
            $Request = Invoke-Endpoint @Param

            if ($Request.access_token) {
                # Save credentials
                $Falcon.Id = $Dynamic.Id.Value
                $Falcon.Secret = $Dynamic.Secret.Value

                if ($Dynamic.CID.Value) {
                    # Save CID
                    $Falcon.CID = $Dynamic.CID.Value
                }
                # Save token and expiration
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] token generated"

                $Falcon.Expires = (Get-Date).AddSeconds($Request.expires_in)
                $Falcon.Token = "$($Request.token_type) $($Request.access_token)"
            } else {
                # Clear cached authentication information
                @('id', 'secret', 'CID', 'token').foreach{
                    if ($Falcon.$_) {
                        $Falcon.$_ = $null
                        Write-Debug "[$($MyInvocation.MyCommand.Name)] cleared $_"
                    }
                }
                # Output error
                $Request
            }
        }
    }
}