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
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [object] $Endpoint,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [object] $Request,

        [Parameter(Position = 3)]
        [hashtable] $Header
    )
    begin {
        # Check existing token
        if ($Endpoint.Name -ne 'oauth2AccessToken') {
            if ((-not($Falcon.Token)) -or (($Falcon.Expires) -le (Get-Date).AddSeconds(30))) {
                Request-FalconToken
            }
        }
        $Authorization = if ($Endpoint.Permission -match ".*:(read|write)") {
            # Bearer token
            $Falcon.token
        } else {
            # Basic authorization
            Get-AuthPair
        }
    }
    process {
        if ($Endpoint.Headers) {
            foreach ($Name in ($Endpoint.Headers | Get-Member -MemberType NoteProperty).Name) {
                # Add headers from endpoint
                $Request.Headers.Add($Name,($Endpoint.Headers.$Name))
            }
        }
        if ($Header) {
            foreach ($Pair in $Header.GetEnumerator()) {
                # Add headers from input
                $Request.Headers.Add($Pair.Key, $Pair.Value)
            }
        }
        if ($Authorization) {
            # Add authorization
            $Request.Headers.Add('Authorization', $Authorization)
        }
    }
}