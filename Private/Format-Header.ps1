function Format-Header {
    <#
    .SYNOPSIS
        Outputs a header for use with Invoke-Endpoint
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER REQUEST
        Request object
    .PARAMETER HEADER
        Additional header values to add from input
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Endpoint,

        [Parameter(Mandatory = $true)]
        [object] $Request,

        [Parameter()]
        [hashtable] $Header
    )
    begin {
        if ($Endpoint.Name -ne 'oauth2/oauth2AccessToken') {
            if ((-not($Falcon.Token)) -or (($Falcon.Expires) -le (Get-Date).AddSeconds(30))) {
                Request-FalconToken
            }
            $Authorization = if ($Endpoint.Permission -match ".*:(read|write)") {
                $Falcon.token
            }
            else {
                Get-AuthPair
            }
        }
    }
    process {
        if ($Endpoint.Headers) {
            foreach ($Name in ($Endpoint.Headers | Get-Member -MemberType NoteProperty).Name) {
                $Request.Headers.Add($Name, ($Endpoint.Headers.$Name))
            }
        }
        if ($Header) {
            foreach ($Pair in $Header.GetEnumerator()) {
                $Request.Headers.Add($Pair.Key, $Pair.Value)
            }
        }
        if ($Authorization) {
            $Request.Headers.Add('Authorization', $Authorization)
        }
        Write-Debug ("[$($MyInvocation.MyCommand.Name)] " +
            "$(ConvertTo-Json ($Request.Headers | Where-Object { $_.Key -NE 'Authorization' }))")
    }
}