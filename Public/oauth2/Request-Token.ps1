function Request-Token {
<#
.SYNOPSIS
    Generate an OAuth2 access token
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER CLOUD
    Destination CrowdStrike cloud [default: 'us-1']
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'oauth2AccessToken')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'oauth2AccessToken',
            HelpMessage = 'Destination CrowdStrike cloud')]
        [ValidateSet('eu-1', 'us-gov-1', 'us-1', 'us-2')]
        [string] $Cloud,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('oauth2AccessToken')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ($Cloud) {
                # Set hostname
                $Falcon.Hostname = switch ($Cloud) {
                    'eu-1' {
                        'https://api.eu-1.crowdstrike.com'
                    }
                    'us-gov-1' {
                        'https://api.laggar.gcw.crowdstrike.com'
                    }
                    'us-1' {
                        'https://api.crowdstrike.com'
                    }
                    'us-2' {
                        'https://api.us-2.crowdstrike.com'
                    }
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
                    $Dynamic.Secret.Value = Read-Host "Secret" -AsSecureString
                }
            } else {
                # Convert dynamic Secret input to SecureString
                $Dynamic.Secret.Value = $Dynamic.Secret.Value | ConvertTo-SecureString -AsPlainText -Force
            }
            Write-Debug "[$($MyInvocation.MyCommand.Name)] id: $($Dynamic.Id.Value)"

            if ((-not($Dynamic.CID.Value)) -and $Falcon.CID) {
                # Collect saved CID
                $Dynamic.CID.Value = $Falcon.CID
            }
            # Base parameters
            $Param = @{
                Endpoint = $Endpoints[0]
                Body = "client_id=$($Dynamic.Id.Value)&client_secret=$(Get-SecureString $Dynamic.Secret.Value)"
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
                $Falcon.Token = "$($Request.token_type) $($Request.access_token)" |
                    ConvertTo-SecureString -AsPlainText -Force

                if (Test-Path "$Home\Falcon.token") {
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] token saved as $Home\Falcon.token"

                    # Update cached token
                    $Falcon.ExportToken()
                }
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