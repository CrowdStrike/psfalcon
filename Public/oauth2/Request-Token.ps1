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
        $Endpoints = @('oauth2/oauth2AccessToken')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            if ($PSBoundParameters.Cloud) {
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
                    $Dynamic.Id.Value = $Falcon.Id
                }
                else {
                    $Dynamic.Id.Value = Read-Host "Id"
                }
            }
            if (-not($Dynamic.Secret.Value)) {
                if ($Falcon.Secret) {
                    $Dynamic.Secret.Value = $Falcon.Secret
                }
                else {
                    $Dynamic.Secret.Value = Read-Host "Secret"
                }
            }
            Write-Debug "[$($MyInvocation.MyCommand.Name)] id: $($Dynamic.Id.Value)"
            if ((-not($Dynamic.CID.Value)) -and $Falcon.CID) {
                $Dynamic.CID.Value = $Falcon.CID
            }
            $Param = @{
                Endpoint = $Endpoints[0]
                Body     = "client_id=$($Dynamic.Id.Value)&client_secret=$($Dynamic.Secret.Value)"
            }
            if ($Dynamic.CID.Value) {
                $Param.Body += "&member_cid=$($Dynamic.CID.Value)"
                Write-Debug "[$($MyInvocation.MyCommand.Name)] cid: $($Dynamic.CID.Value)"
            }
            $Request = Invoke-Endpoint @Param
            if ($Request.access_token) {
                $Falcon.Id = $Dynamic.Id.Value
                $Falcon.Secret = $Dynamic.Secret.Value
                if ($Dynamic.CID.Value) {
                    $Falcon.CID = $Dynamic.CID.Value
                }
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] token generated"
                $Falcon.Expires = (Get-Date).AddSeconds($Request.expires_in)
                $Falcon.Token = "$($Request.token_type) $($Request.access_token)"
            }
            else {
                @('id', 'secret', 'CID', 'token').foreach{
                    if ($Falcon.$_) {
                        $Falcon.$_ = $null
                        Write-Debug "[$($MyInvocation.MyCommand.Name)] cleared $_"
                    }
                }
                $Request
            }
        }
    }
}