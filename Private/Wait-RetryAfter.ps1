function Wait-RetryAfter {
<#
.SYNOPSIS
    Checks a Falcon API response for rate limiting and waits
.PARAMETER HEADERS
    Response headers from Falcon endpoint
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [object] $Headers
    )
    process {
        if ($Headers.Key -contains 'X-Ratelimit-RetryAfter') {
            # Wait for rate limiting
            $RetryAfter = ($Headers.GetEnumerator() | Where-Object {
                $_.Key -eq 'X-Ratelimit-RetryAfter' }).Value
            $Wait = ($RetryAfter - ([int] (Get-Date -UFormat %s) + 1))

            Write-Verbose "[$($MyInvocation.MyCommand.Name)] rate limited for $Wait seconds"

            Start-Sleep -Seconds $Wait
        }
    }
}