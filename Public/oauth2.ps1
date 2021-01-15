function Request-Token {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/oauth2/token:post')
        return (Get-Dictionary -Endpoints $Endpoints)
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
            @('ClientId', 'ClientSecret', 'MemberCid') | ForEach-Object {
                if (-not($PSBoundParameters.$_)) {
                    if ($Falcon.$_) {
                        $PSBoundParameters.$_ = $Falcon.$_
                    } elseif ($_ -NE 'MemberCid') {
                        $Falcon.$_ = Read-Host "$_"
                    }
                } else {
                    $Falcon.$_ = $PSBoundParameters.$_
                }
            }
            $Param = @{
                Endpoint = $Endpoints[0]
                Body     = "client_id=$($Falcon.ClientId)&client_secret=$($Falcon.ClientSecret)"
            }
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] hostname: $($Falcon.Hostname)"
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] client_id: $($Falcon.ClientId)"
            if ($Falcon.MemberCid) {
                $Param.Body += "&member_cid=$($Falcon.MemberCid.ToLower())"
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] member_cid: $($Falcon.MemberCid.ToLower())"
            }
            $Request = Invoke-Endpoint @Param
            if ($Request.access_token) {
                $Falcon.Expires = (Get-Date).AddSeconds($Request.expires_in)
                $Falcon.Token = "$($Request.token_type) $($Request.access_token)"
            }
            else {
                Clear-Auth
            }
        }
    }
}
function Revoke-Token {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/oauth2/revoke:post')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/oauth2/revoke:post')
        return (Get-Dictionary -Endpoints $Endpoints)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            if ($Falcon.Token -and ($Falcon.Expires -gt (Get-Date))) {
                $Param = @{
                    Endpoint = $Endpoints[0]
                    Body     = "token=$($Falcon.token -replace 'bearer ', '')"
                }
                Invoke-Endpoint @Param
            }
            Clear-Auth
        }
    }
}
