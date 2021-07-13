function Request-FalconToken {
<#
.Synopsis
    Request an OAuth2 access token
.Parameter ClientId
    OAuth2 Client Identifier
.Parameter ClientSecret
    OAuth2 Client Secret
.Parameter Hostname
    CrowdStrike destination hostname [default: 'https://api.crowdstrike.com']
.Parameter MemberCid
    Member CID, required when authenticating with a child within a parent/child CID environment
#>
    [CmdletBinding(DefaultParameterSetName = '/oauth2/token:post')]
    param(
        [Parameter(ParameterSetName = '/oauth2/token:post', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $ClientId,

        [Parameter(ParameterSetName = '/oauth2/token:post', Position = 2)]
        [ValidatePattern('^\w{40}$')]
        [string] $ClientSecret,

        [Parameter(ParameterSetName = '/oauth2/token:post', Position = 3)]
        [ValidateSet('https://api.crowdstrike.com', 'https://api.us-2.crowdstrike.com',
            'https://api.laggar.gcw.crowdstrike.com', 'https://api.eu-1.crowdstrike.com' )]
        [string] $Hostname,

        [Parameter(ParameterSetName = '/oauth2/token:post', Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [string] $MemberCid
    )
    begin {
        function Get-ApiCredential ($Inputs) {
            $Output = @{}
            @('ClientId', 'ClientSecret', 'Hostname', 'MemberCid').foreach{
                $Value = if ($Inputs.$_) {
                    # Use input
                    $Inputs.$_
                } elseif ($Script:Falcon.$_) {
                    # Use ApiClient value
                    $Script:Falcon.$_
                }
                if (!$Value -and $_ -match '^(ClientId|ClientSecret)$') {
                    # Prompt for ClientId/ClientSecret
                    $Value = Read-Host $_
                } elseif (!$Value -and $_ -eq 'Hostname') {
                    # Default to 'us-1' cloud
                    $Value = 'https://api.crowdstrike.com'
                }
                if ($Value) {
                    $Output.Add($_, $Value)
                }
            }
            return $Output
        }
        if (!$Script:Falcon) {
            # Initiate ApiClient and set SslProtocol
            $Script:Falcon = Get-ApiCredential $PSBoundParameters
            $Script:Falcon.Add('Api', [ApiClient]::New())
            $Script:Falcon.Api.Handler.SslProtocols = 'Tls12'
        } else {
            ($PSBoundParameters).GetEnumerator().foreach{
                if ($Script:Falcon.($_.Key) -ne $_.Value) {
                    # Update existing ApiClient with new input
                    $Script:Falcon.($_.Key) = $_.Value
                }
            }
        }
    }
    process {
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)$(($PSCmdlet.ParameterSetName).Split(':')[0])"
            Method  = ($PSCmdlet.ParameterSetName).Split(':')[1]
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/x-www-form-urlencoded'
            }
            Body = "client_id=$($Script:Falcon.ClientId)&client_secret=$($Script:Falcon.ClientSecret)"
        }
        if ($Script:Falcon.MemberCid) {
            $Param.Body += "&member_cid=$($Script:Falcon.MemberCid)"
        }
        $Response = $Script:Falcon.Api.Invoke($Param)
        if ($Response.Result.StatusCode -and @(308,429) -contains $Response.Result.StatusCode.GetHashCode()) {
            # Re-run command when redirected or rate limited
            & $MyInvocation.MyCommand.Name
        } elseif ($Response.Result) {
            # Update ApiClient hostname if redirected
            $Region = $Response.Result.Headers.GetEnumerator().Where({ $_.Key -eq 'X-Cs-Region' }).Value
            $Redirect = switch ($Region) {
                'us-1'     { 'https://api.crowdstrike.com' }
                'us-2'     { 'https://api.us-2.crowdstrike.com' }
                'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com' }
                'eu-1'     { 'https://api.eu-1.crowdstrike.com' }
            }
            if ($Redirect -and $Script:Falcon.Hostname -ne $Redirect) {
                Write-Verbose "[Request-FalconToken] Redirected to '$Region'"
                $Script:Falcon.Hostname = $Redirect
            }
            $Result = Write-Result $Response
            if ($Result.access_token) {
                # Cache access token in ApiClient
                $Token = "$($Result.token_type) $($Result.access_token)"
                if (!$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
                    $Script:Falcon.Api.Client.DefaultRequestHeaders.Add('Authorization', $Token)
                } else {
                    $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization = $Token
                }
                $Script:Falcon.Expiration = (Get-Date).AddSeconds($Result.expires_in)
                Write-Verbose "[Request-FalconToken] Authorized until: $($Script:Falcon.Expiration)"
            }
        }
    }
}
function Revoke-FalconToken {
<#
.Synopsis
    Revoke your active OAuth2 token and clear cached credentials
#>
    [CmdletBinding(DefaultParameterSetName = '/oauth2/revoke:post')]
    param()
    process {
        if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
            # Revoke OAuth2 access token
            $Param = @{
                Path    = "$($Script:Falcon.Hostname)$(($PSCmdlet.ParameterSetName).Split(':')[0])"
                Method  = ($PSCmdlet.ParameterSetName).Split(':')[1]
                Headers = @{
                    Accept        = 'application/json'
                    ContentType   = 'application/x-www-form-urlencoded'
                    Authorization = "basic $([System.Convert]::ToBase64String(
                        [System.Text.Encoding]::ASCII.GetBytes(
                        "$($Script:Falcon.ClientId):$($Script:Falcon.ClientSecret)")))"
                }
                Body    = "token=$($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization -replace
                    'bearer ', '')"
            }
            Write-Result ($Script:Falcon.Api.Invoke($Param))
        }
        Remove-Variable -Name Falcon -Scope Script
    }
}
function Test-FalconToken {
<#
.Synopsis
    Display current authorization token information
#>
    [CmdletBinding()]
    param()
    process {
        if ($Script:Falcon) {
            [PSCustomObject] @{
                Token = if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization -and
                ($Script:Falcon.Expiration -gt (Get-Date).AddSeconds(15))) {
                    $true
                } else {
                    $false
                }
                Hostname = $Falcon.Hostname
                ClientId = $Falcon.ClientId
                MemberCid = $Falcon.MemberCid
            }
        }
    }
}