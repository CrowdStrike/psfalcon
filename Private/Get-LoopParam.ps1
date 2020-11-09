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
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        $Output = @{ }
    }
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet |
            Where-Object Name -NotMatch '(offset|after|detailed|all)')) {
            $Output[$Item.Name] = $Item.Value
        }
        $Output
    }
}