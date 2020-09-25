function Get-Param {
<#
.SYNOPSIS
    Creates a 'splat' hashtable for Invoke-Endpoint
.PARAMETER ENDPOINT
    Falcon endpoint name
.PARAMETER DYNAMIC
    A runtime parameter dictionary to search for input values
.PARAMETER MAX
    A maximum number of identifiers per request
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [string] $Endpoint,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [System.Collections.ArrayList] $Dynamic,

        [Parameter(Position = 3)]
        [int] $Max
    )
    begin {
        # Set Falcon endpoint target
        $Target = $Falcon.Endpoint($Endpoint)

        # Create output object
        $Output = @{
            Endpoint = $Endpoint
        }
    }
    process {
        # Check dictionary for input matching endpoint target
        @('Body', 'Formdata', 'Header', 'Outfile', 'Path', 'Query') | ForEach-Object {
            # Create variable for each input type
            New-Variable -Name $_ -Value (& "Get-$_" $Target $Dynamic)

            if ((Get-Variable $_).Value) {
                # Add results to output
                $Output[$_] = (Get-Variable $_).Value
            }
        }
        if ($Max) {
            # Output result in groups of $Max
            Split-Param $Output $Max
        } else {
            # Check for maximum and output in groups
            Split-Param $Output
        }
    }
}