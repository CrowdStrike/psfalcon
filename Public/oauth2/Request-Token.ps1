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
            $Falcon.Hostname = switch ($PSBoundParameters.Cloud) {
                'eu-1' { 'https://api.eu-1.crowdstrike.com' }
                'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com' }
                'us-1' { 'https://api.crowdstrike.com' }
                'us-2' { 'https://api.us-2.crowdstrike.com' }
                default { 'https://api.crowdstrike.com' }
            }
            @('Id', 'Secret', 'CID') | ForEach-Object {
                if (($_ -NE 'CID') -and (-not($Dynamic.$_.Value))) {
                    $Dynamic.$_.Value = Read-Host "$_"
                }
                if ($Dynamic.$_.Value) {
                    $Falcon.$_ = $Dynamic.$_.Value
                }
            }
            $Param = @{
                Endpoint = $Endpoints[0]
                Body     = "client_id=$($Falcon.Id)&client_secret=$($Falcon.Secret)"
            }
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] hostname: $($Falcon.Hostname)"
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] id: $($Falcon.Id)"
            if ($Falcon.CID) {
                $Param.Body += "&member_cid=$($Falcon.CID)"
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] cid: $($Falcon.CID)"
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