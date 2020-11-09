function Get-AuthPair {
    <#
    .SYNOPSIS
        Outputs an authorization pair for Format-Header
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    process {
        if ($Falcon.Id -and $Falcon.Secret) {
            "basic $([System.Convert]::ToBase64String(
                [System.Text.Encoding]::ASCII.GetBytes("$($Falcon.Id):$($Falcon.Secret)")))"
        }
        else {
            $null
        }
    }
}