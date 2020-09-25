function Get-LoopParam {
<#
.SYNOPSIS
    Creates a 'splat' hashtable for Invoke-Loop
.PARAMETER DYNAMIC
    A runtime parameter dictionary to search for input values
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        # Create output object
        $Output = @{ }
    }
    process {
        # Evaluate dynamic parameter input (excluding pagination)
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet | Where-Object Name -notmatch '(offset|after)')) {
            # Add key/value to output
            $Output[$Item.Name] = $Item.Value
        }
        # Output result
        $Output
    }
}