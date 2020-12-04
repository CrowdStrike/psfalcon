function Format-Param {
    <#
    .SYNOPSIS
        Converts a 'splat' hashtable body into Json
    .PARAMETER PARAM
        Parameter hashtable
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Param
    )
    process {
        if ($Param.Body -and ($Falcon.Endpoint($Param.Endpoint)).Headers.ContentType -eq 'application/json') {
            $Param.Body = ConvertTo-Json $Param.Body -Depth 8
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $($Param.Body)"
        }
    }
}