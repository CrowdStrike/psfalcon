function Request-FalconToken {
    [CmdletBinding(DefaultParameterSetName = 'Hostname')]
    param(
        [Parameter(ParameterSetName = 'Cloud', ValueFromPipelineByPropertyName = $true, Position = 1)]
        [Parameter(ParameterSetName = 'Hostname', ValueFromPipelineByPropertyName = $true, Position = 1)]
        [Alias('client_id')]
        [ValidatePattern('^\w{32}$')]
        [string] $ClientId,

        [Parameter(ParameterSetName = 'Cloud', ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Parameter(ParameterSetName = 'Hostname', ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Alias('client_secret')]
        [ValidatePattern('^\w{40}$')]
        [string] $ClientSecret,

        [Parameter(ParameterSetName = 'Cloud', ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateSet('eu-1', 'us-gov-1', 'us-1', 'us-2')]
        [string] $Cloud,

        [Parameter(ParameterSetName = 'Hostname', ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateSet('https://api.crowdstrike.com', 'https://api.us-2.crowdstrike.com',
            'https://api.laggar.gcw.crowdstrike.com', 'https://api.eu-1.crowdstrike.com')]
        [string] $Hostname,

        [Parameter(ParameterSetName = 'Cloud', ValueFromPipelineByPropertyName = $true, Position = 4)]
        [Parameter(ParameterSetName = 'Hostname', ValueFromPipelineByPropertyName = $true, Position = 4)]
        [Alias('cid', 'member_cid')]
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
                } elseif ($null -ne $Script:Falcon.$_) {
                    # Use ApiClient value
                    $Script:Falcon.$_
                }
                if (!$Value -and $_ -match '^(ClientId|ClientSecret)$') {
                    # Prompt for ClientId/ClientSecret and validate input
                    $Value = Read-Host $_
                    $BaseError = 'Cannot validate argument on parameter "{0}". The argument "{1}" does not ' +
                        'match the "{2}" pattern. Supply an argument that matches "{2}" and try the command again.'
                    $ValidPattern = if ($_ -eq 'ClientId') {
                        '^\w{32}$'
                    } else {
                        '^\w{40}$'
                    }
                    if ($Value -notmatch $ValidPattern) {
                        $InvalidValue = $BaseError -f $_, $Value, $ValidPattern
                        throw $InvalidValue
                    }
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
    }
    process {
        if ($PSBoundParameters.Cloud) {
            # Convert 'Cloud' to 'Hostname'
            $Value = switch ($PSBoundParameters.Cloud) {
                'eu-1'     { 'https://api.eu-1.crowdstrike.com' }
                'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com' }
                'us-1'     { 'https://api.crowdstrike.com' }
                'us-2'     { 'https://api.us-2.crowdstrike.com' }
            }
            $PSBoundParameters['Hostname'] = $Value
            [void] $PSBoundParameters.Remove('Cloud')
        }
        if (!$Script:Falcon) {
            try {
                # Initiate ApiClient, set SslProtocol and UserAgent
                $Script:Falcon = Get-ApiCredential $PSBoundParameters
                $Script:Falcon.Add('Api', [ApiClient]::New())
                if ($Script:Falcon.Api) {
                    try {
                        # Set TLS 1.2 for [System.Net.Http.HttpClientHandler]
                        $Script:Falcon.Api.Handler.SslProtocols = 'Tls12'
                        Write-Verbose "[Request-FalconToken] Set TLS 1.2 via [System.Net.Http.HttpClientHandler]"
                    } catch {
                        # Set TLS 1.2 for PowerShell session if not set already
                        if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
                            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                            Write-Verbose "[Request-FalconToken] Set TLS 1.2 via [Net.ServicePointManager]"
                        }
                    }
                    $Script:Falcon.Api.Handler.AutomaticDecompression = [System.Net.DecompressionMethods]::Gzip,
                        [System.Net.DecompressionMethods]::Deflate
                    $Script:Falcon.Api.Client.DefaultRequestHeaders.UserAgent.ParseAdd(
                        "$((Show-FalconModule).UserAgent)")
                } else {
                    Write-Error "Unable to initialize [ApiClient] object."
                }
            } catch {
                throw $_
            }
        } else {
            (Get-ApiCredential $PSBoundParameters).GetEnumerator().foreach{
                if ($Script:Falcon.($_.Key) -ne $_.Value) {
                    # Update existing ApiClient with new input
                    $Script:Falcon.($_.Key) = $_.Value
                }
            }
        }
        if ($Script:Falcon.ClientId -and $Script:Falcon.ClientSecret) {
            $Param = @{
                Path    = "$($Script:Falcon.Hostname)/oauth2/token"
                Method  = 'post'
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
            if ($Response.Result) {
                $Region = $Response.Result.Headers.GetEnumerator().Where({ $_.Key -eq 'X-Cs-Region' }).Value
                $Redirect = switch ($Region) {
                    # Update ApiClient hostname if redirected
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
                } elseif (@(308,429) -contains $Response.Result.StatusCode.GetHashCode()) {
                    # Retry token request when rate limited or unable to automatically follow redirection
                    & $MyInvocation.MyCommand.Name
                }
            } else {
                @('ClientId', 'ClientSecret', 'MemberCid').foreach{
                    [void] $Script:Falcon.Remove("$_")
                }
                [void] $Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
                throw 'Authorization token request failed.'
            }
        } else {
            throw 'Missing required credentials.'
        }
    }
}
function Revoke-FalconToken {
    [CmdletBinding(DefaultParameterSetName = '/oauth2/revoke:post')]
    param()
    process {
        if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization.Parameter -and
        $Script:Falcon.ClientId -and $Script:Falcon.ClientSecret) {
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
                Body    = "token=$($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization.Parameter)"
            }
            Write-Result ($Script:Falcon.Api.Invoke($Param))
            [void] $Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
        }
        @('ClientId', 'ClientSecret', 'MemberCid').foreach{
            [void] $Script:Falcon.Remove("$_")
        }
    }
}
function Test-FalconToken {
    [CmdletBinding()]
    param()
    process {
        if ($Script:Falcon) {
            [PSCustomObject] @{
                Token     = if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization -and
                ($Script:Falcon.Expiration -gt (Get-Date).AddSeconds(15))) {
                    $true
                } else {
                    $false
                }
                Hostname  = $Script:Falcon.Hostname
                ClientId  = $Script:Falcon.ClientId
                MemberCid = $Script:Falcon.MemberCid
            }
        } else {
            Write-Error "No authorization token available. Try 'Request-FalconToken'."
        }
    }
}
