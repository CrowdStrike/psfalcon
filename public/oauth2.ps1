function Request-FalconToken {
<#
.SYNOPSIS
Request an OAuth2 access token
.DESCRIPTION
If successful, your credentials ('ClientId', 'ClientSecret', 'MemberCid' and 'Cloud'/'CustomUrl'/'Hostname') and
token are cached for re-use.

If an active OAuth2 access token is due to expire in less than 240 seconds, a new token will automatically
be requested using your cached credentials.

The 'Collector' parameter allows for the submission of a [System.Collections.Hashtable] object containing the
parameters included with a 'Register-FalconEventCollector' command ('Path', 'Token' and 'Enable') in order to
log an initial OAuth2 access token request.
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER CustomUrl
Custom API URL for module troubleshooting
.PARAMETER Hostname
CrowdStrike API hostname [default: 'https://api.crowdstrike.com']
.PARAMETER MemberCid
Member CID, used when authenticating within a multi-CID environment ('Falcon Flight Control')
.PARAMETER Collector
A hashtable containing 'Path', 'Token' and 'Enable' properties for 'Register-FalconEventCollector'
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Request-FalconToken
#>
  [CmdletBinding(DefaultParameterSetName='/oauth2/token:post',SupportsShouldProcess)]
  [OutputType([void])]
  param(
    [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=1)]
    [Parameter(ParameterSetName='Custom',ValueFromPipelineByPropertyName,Position=1)]
    [Parameter(ParameterSetName='/oauth2/token:post',ValueFromPipelineByPropertyName,Position=1)]
    [Alias('client_id')]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ClientId,
    [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=2)]
    [Parameter(ParameterSetName='Custom',ValueFromPipelineByPropertyName,Position=2)]
    [Parameter(ParameterSetName='/oauth2/token:post',ValueFromPipelineByPropertyName,Position=2)]
    [Alias('client_secret')]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,
    [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('eu-1','us-1','us-2','us-gov-1','us-gov-2',IgnoreCase=$false)]
    [string]$Cloud,
    [Parameter(ParameterSetName='Custom',ValueFromPipelineByPropertyName,Position=3)]
    [string]$CustomUrl,
    [Parameter(ParameterSetName='/oauth2/token:post',ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
      'https://api.laggar.gcw.crowdstrike.com','https://api.us-gov-2.crowdstrike.mil',
      'https://api.eu-1.crowdstrike.com',IgnoreCase=$false)]
    [string]$Hostname,
    [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=4)]
    [Parameter(ParameterSetName='Custom',ValueFromPipelineByPropertyName,Position=4)]
    [Parameter(ParameterSetName='/oauth2/token:post',ValueFromPipelineByPropertyName,Position=4)]
    [Alias('cid','member_cid')]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$MemberCid,
    [Parameter(ParameterSetName='Cloud',ValueFromPipelineByPropertyName,Position=5)]
    [Parameter(ParameterSetName='Custom',ValueFromPipelineByPropertyName,Position=5)]
    [Parameter(ParameterSetName='/oauth2/token:post',ValueFromPipelineByPropertyName,Position=5)]
    [ValidateScript({
      @($_.Keys).foreach{
        if ($_ -notmatch '^(Enable|Token|Uri)$') { throw "Unexpected key in 'Collector' object. ['$_']" }
      }
      foreach ($Key in @('Token','Uri')) {
        if ($_.Keys -notcontains $Key) { throw "'Collector' requires '$Key'." } else { $true }
      }
    })]
    [System.Collections.Hashtable]$Collector
  )
  begin {
    function Get-ApiCredential ($UserInput) {
      $Output = @{}
      @('ClientId','ClientSecret','Hostname','MemberCid').foreach{
        # Use input before existing ApiClient value
        $Value = if ($UserInput.$_) { $UserInput.$_ } elseif ($null -ne $Script:Falcon.$_) { $Script:Falcon.$_ }
        if (!$Value -and $_ -match '^(ClientId|ClientSecret)$') {
          # Prompt for ClientId/ClientSecret and validate input
          $Value = Read-Host $_
          $BaseError = 'Cannot validate argument on parameter "{0}". The argument "{1}" does not match the "{2}"' +
            ' pattern. Supply an argument that matches "{2}" and try the command again.'
          $ValidPattern = if ($_ -eq 'ClientId') { '^[a-fA-F0-9]{32}$' } else { '^\w{40}$' }
          if ($Value -notmatch $ValidPattern) {
            $InvalidValue = $BaseError -f $_,$Value,$ValidPattern
            throw $InvalidValue
          }
        } elseif (!$Value -and !$UserInput.CustomUrl -and $_ -eq 'Hostname') {
          # Default to 'us-1' cloud
          $Value = 'https://api.crowdstrike.com'
        }
        if ($Value) { $Output.Add($_,$Value) }
      }
      return $Output
    }
  }
  process {
    if ($PSBoundParameters.MemberCid) {
      # Validate MemberCid value
      $PSBoundParameters.MemberCid = Confirm-CidValue $PSBoundParameters.MemberCid
    }
    if ($PSBoundParameters.CustomUrl) {
      # Override Hostname with CustomUrl
      $PSBoundParameters['Hostname'] = $PSBoundParameters.CustomUrl
      [void]$PSBoundParameters.Remove('CustomUrl')
    } elseif ($PSBoundParameters.Cloud) {
      # Convert 'Cloud' to 'Hostname'
      $Value = switch ($PSBoundParameters.Cloud) {
        'eu-1' { 'https://api.eu-1.crowdstrike.com' }
        'us-1' { 'https://api.crowdstrike.com' }
        'us-2' { 'https://api.us-2.crowdstrike.com' }
        'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com' }
        'us-gov-2' { 'https://api.us-gov-2.crowdstrike.mil' }
      }
      $PSBoundParameters['Hostname'] = $Value
      [void]$PSBoundParameters.Remove('Cloud')
    }
    if (!$Script:Falcon) {
      try {
        # Initiate ApiClient, set SslProtocol and UserAgent
        $Script:Falcon = Get-ApiCredential $PSBoundParameters
        $Script:Falcon.Add('Api',[ApiClient]::New())
        if ($Script:Falcon.Api) {
          [string]$String = try {
            # Set TLS 1.2 for [System.Net.Http.HttpClientHandler]
            $Script:Falcon.Api.Handler.SslProtocols = 'Tls12'
            '[System.Net.Http.HttpClientHandler]'
          } catch {
            if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
              # Set TLS 1.2 for PowerShell session
              [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
              '[Net.ServicePointManager]'
            }
          }
          if ($String) { Write-Log 'Request-FalconToken' "Set TLS 1.2 via $String." }
          $Script:Falcon.Api.Handler.AutomaticDecompression = [System.Net.DecompressionMethods]::Gzip,
            [System.Net.DecompressionMethods]::Deflate
          $Script:Falcon.Api.Client.DefaultRequestHeaders.UserAgent.ParseAdd($Script:Falcon.Api.UserAgent)
        } else {
          $PSCmdlet.WriteError(
            [System.Management.Automation.ErrorRecord]::New(
              [Exception]::New('Failed to initialize [ApiClient] object.'),
              'failed_to_initialize_api_client_object',
              [System.Management.Automation.ErrorCategory]::ObjectNotFound,
              $null
            )
          )
        }
        [string]$FormatPath = Join-Path (Show-FalconModule).ModulePath (Join-Path format format.json)
        if ((Test-Path $FormatPath) -eq $false) { throw "Unable to find 'format.json'." }
        $Script:Falcon.Add('Format',((Get-Content $FormatPath | ConvertFrom-Json)))
        if ($Script:Falcon.Format) { Write-Log 'Request-FalconToken' "Loaded 'format.json'." }
      } catch {
        throw $_
      }
    } else {
      (Get-ApiCredential $PSBoundParameters).GetEnumerator().foreach{
        # Update existing ApiClient with new input
        if ($Script:Falcon.($_.Key) -ne $_.Value) { $Script:Falcon.($_.Key) = $_.Value }
      }
    }
    if ($PSBoundParameters.Collector) {
      $Collector = $PSBoundParameters.Collector
      Register-FalconEventCollector @Collector
    }
    if ($Script:Falcon.ClientId -and $Script:Falcon.ClientSecret) {
      try {
        $Param = @{
          Path = $Script:Falcon.Hostname,'oauth2/token' -join '/'
          Method = 'post'
          Headers = @{ Accept = 'application/json'; ContentType = 'application/x-www-form-urlencoded' }
          Body = "client_id=$($Script:Falcon.ClientId)&client_secret=$($Script:Falcon.ClientSecret)"
        }
        if ($Script:Falcon.MemberCid) { $Param.Body += "&member_cid=$($Script:Falcon.MemberCid)" }
        $Request = $Script:Falcon.Api.Invoke($Param)
        if ($Request.Result) {
          $Region = $Request.Result.Headers.GetEnumerator().Where({$_.Key -eq 'X-Cs-Region'}).Value
          $Redirect = switch ($Region) {
            # Update ApiClient hostname if redirected
            'eu-1' { 'https://api.eu-1.crowdstrike.com' }
            'us-1' { 'https://api.crowdstrike.com' }
            'us-2' { 'https://api.us-2.crowdstrike.com' }
            'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com' }
            'us-gov-2' { 'https://api.us-gov-2.crowdstrike.mil' }
          }
          if ($Redirect -and $Script:Falcon.Hostname -ne $Redirect) {
            Write-Log 'Request-FalconToken' "Redirected to '$Region'."
            $Script:Falcon.Hostname = $Redirect
          }
          if (@(308,429) -contains $Request.Result.StatusCode.GetHashCode()) {
            # Retry token request when rate limited or unable to automatically follow redirection
            & $MyInvocation.MyCommand.Name
          } else {
            $Result = Write-Result (ConvertFrom-Json (
              $Request.Result.Content).ReadAsStringAsync().Result)
            if ($Result.token_type -and $Result.access_token -and $Result.expires_in) {
              # Cache access token in ApiClient
              [string]$Token = $Result.token_type,$Result.access_token -join ' '
              if (!$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
                $Script:Falcon.Api.Client.DefaultRequestHeaders.Add('Authorization',$Token)
              } else {
                $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization = $Token
              }
              $Script:Falcon.Expiration = (Get-Date).AddSeconds($Result.expires_in)
              Write-Log 'Request-FalconToken' "Authorized until: $($Script:Falcon.Expiration)"
            }
          }
        }
      } catch {
        @('ClientId','ClientSecret','MemberCid').foreach{ [void]$Script:Falcon.Remove($_) }
        [void]$Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
        throw $_
      }
    } else {
      throw 'Missing required credentials.'
    }
  }
}
function Revoke-FalconToken {
<#
.SYNOPSIS
Revoke your active OAuth2 access token
.DESCRIPTION
Revokes your active OAuth2 access token and clears cached credential information ('ClientId', 'ClientSecret',
'MemberCid', 'Cloud'/'Hostname') from the module.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Revoke-FalconToken
#>
  [CmdletBinding(DefaultParameterSetName='/oauth2/revoke:post',SupportsShouldProcess)]
  param()
  process {
    if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization.Parameter -and
    $Script:Falcon.ClientId -and $Script:Falcon.ClientSecret) {
      # Revoke OAuth2 access token
      $Param = @{
        Path = $Script:Falcon.Hostname,'oauth2/revoke' -join '/'
        Method = 'post'
        Headers = @{
          Accept = 'application/json'
          ContentType = 'application/x-www-form-urlencoded'
          Authorization = "basic $([System.Convert]::ToBase64String(
            [System.Text.Encoding]::ASCII.GetBytes(($Script:Falcon.ClientId,
              $Script:Falcon.ClientSecret -join ':'))))"
        }
        Body = 'token',$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization.Parameter -join '='
      }
      $Request = $Script:Falcon.Api.Invoke($Param)
      Write-Result $Request
      [void]$Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
    }
    @('ClientId','ClientSecret','MemberCid').foreach{
      if ($Script:Falcon.$_) { [void]$Script:Falcon.Remove($_) }
    }
  }
}
function Show-FalconToken {
<#
.SYNOPSIS
Display your current OAuth2 access token value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Show-FalconToken
#>
  [CmdletBinding()]
  param()
  process {
    if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization.Parameter) {
      $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization.Parameter
    } else {
      $PSCmdlet.WriteError(
        [System.Management.Automation.ErrorRecord]::New(
          [Exception]::New('No access token available. Try "Request-FalconToken".'),
          'no_access_request_made',
          [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
          $null
        )
      )
    }
  }
}
function Test-FalconToken {
<#
.SYNOPSIS
Display OAuth2 access token status
.DESCRIPTION
Displays a [PSCustomObject] containing token status ('Token') along with cached 'Hostname', 'ClientId' and
'MemberCid' values.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Test-FalconToken
#>
  [CmdletBinding()]
  param()
  process {
    if ($Script:Falcon) {
      [PSCustomObject]@{
        Token = if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization -and
          ($Script:Falcon.Expiration -gt (Get-Date).AddSeconds(240))) { $true } else { $false }
        Hostname = $Script:Falcon.Hostname
        ClientId = $Script:Falcon.ClientId
        MemberCid = $Script:Falcon.MemberCid
      }
    } else {
      $PSCmdlet.WriteError(
        [System.Management.Automation.ErrorRecord]::New(
          [Exception]::New('No access token available. Try "Request-FalconToken".'),
          'no_access_request_made',
          [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
          $null
        )
      )
    }
  }
}