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
        $Authorization = if ($Endpoint.Permission -match ".*:(read|write)") {
            $Falcon.token
        }
        else {
            Get-AuthPair
        }
    }
    process {
        if ($Endpoint.Headers) {
            foreach ($Pair in $Endpoint.Headers.GetEnumerator()) {
                $Request.Headers.Add($Pair.Key, $Pair.Value)
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
        $VerboseHeader = ($Request.Headers.GetEnumerator() |
            Where-Object { $_.Key -NE 'Authorization' }).foreach{ "$($_.Key): '$($_.Value)'" } -join ', '
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $VerboseHeader"
    }
}