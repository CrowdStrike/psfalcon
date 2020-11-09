function Clear-Auth {
    <#
    .SYNOPSIS
        Removes cached authentication and token information
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    process {
        @('Id', 'Secret', 'CID', 'Token').foreach{
            if ($Falcon.$_) {
                $Falcon.$_ = $null
            }
        }
        $Falcon.Expires = Get-Date
    }
}