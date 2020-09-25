function Get-SecureString {
<#
.SYNOPSIS
    Converts a SecureString to plaintext
.PARAMETER STRING
    SecureString to convert to plaintext
.PARAMETER DYNAMIC
    A runtime parameter dictionary to search for input values
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [SecureString] $String
    )
    process {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            # Output text using PowerShell
            $String | ConvertFrom-SecureString -AsPlainText
        } else {
            # Output text using .NET
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($String))
        }
    }
}