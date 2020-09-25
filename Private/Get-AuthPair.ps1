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
            # Output base64 encoded Username/Password pair
            "basic $([System.Convert]::ToBase64String(
                [System.Text.Encoding]::ASCII.GetBytes("$($Falcon.Id):$(Get-SecureString $Falcon.Secret)")))"
        } else {
            $null
        }
    }
}