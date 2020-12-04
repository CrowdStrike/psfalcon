function Request-Token {
    <#
    .SYNOPSIS
        Generate an OAuth2 access token
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'oauth2/oauth2AccessToken')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('oauth2/oauth2AccessToken')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            if (-not($PSBoundParameters.Cloud)) {
                if (-not($Falcon.Hostname)) {
                    $PSBoundParameters.Cloud = 'us-1'
                }
            }
            if ($PSBoundParameters.Cloud) {
                $Falcon.Hostname = switch ($PSBoundParameters.Cloud) {
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
            }
            @('Id', 'Secret', 'CID') | ForEach-Object {
                if (-not($PSBoundParameters.$_)) {
                    if ($Falcon.$_) {
                        $PSBoundParameters.$_ = $Falcon.$_
                    } elseif ($_ -NE 'CID') {
                        $Falcon.$_ = Read-Host "$_"
                    }
                } else {
                    $Falcon.$_ = $PSBoundParameters.$_
                }
            }
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] hostname: $($Falcon.Hostname)"
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] id: $($Falcon.Id)"
            $Param = @{
                Endpoint = $Endpoints[0]
                Body     = "client_id=$($Falcon.Id)&client_secret=$($Falcon.Secret)"
            }
            if ($Falcon.CID) {
                $Param.Body += "&member_cid=$($Falcon.CID.ToLower())"
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] cid: $($Falcon.CID.ToLower())"
            }
            $Request = Invoke-Endpoint @Param
            if ($Request.access_token) {
                $Falcon.Expires = (Get-Date).AddSeconds($Request.expires_in)
                $Falcon.Token = "$($Request.token_type) $($Request.access_token)"
            }
            else {
                Clear-Auth
                $Request
            }
        }
    }
}