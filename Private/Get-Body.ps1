function Get-Body {
<#
.SYNOPSIS
    Outputs body parameters from input
.PARAMETER ENDPOINT
    Falcon endpoint
.PARAMETER DYNAMIC
    A runtime parameter dictionary to search for input values
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [object] $Endpoint,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            # Add System.Net.Http
            Add-Type -AssemblyName System.Net.Http
        }
    }
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = if ($Endpoint.Parameters.Dynamic -contains $Item.Name) {
                # Match input parameter with endpoint
                $Endpoint.Parameters | Where-Object Dynamic -eq $Item.Name
            } else {
                # Match input with SharedParameters
                $Falcon.Endpoint('private/SharedParameters').Parameters | Where-Object Dynamic -eq $Item.Name
            }
            if ($Param.In -match 'body') {
                if ($Param.Name -eq 'body') {
                    # Capture filename for debug output
                    $Filename = $Item.Value

                    $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
                        # Convert to bytes in PowerShell 6+
                        Get-Content $Item.Value -AsByteStream
                    } else {
                        # Convert to bytes in PowerShell 5.1
                        Get-Content $Item.Value -Encoding Byte -Raw
                    }
                    # Convert to ByteArrayContent
                    $ByteArray = [System.Net.Http.ByteArrayContent]::New($ByteStream)

                    # Add Content-Type from endpoint
                    $ByteArray.Headers.Add('Content-Type', $Endpoint.Headers.ContentType)
                } else {
                    if (-not($BodyOutput)) {
                        # Create output object
                        $BodyOutput = @{ }
                    }
                    if ($Param.Parent) {
                        if (-not($Parents)) {
                            # Create object to contain 'parents'
                            $Parents = @{ }
                        }
                        if (-not($Parents.($Param.Parent))) {
                            # Add table to parents
                            $Parents[$Param.Parent] = @{ }
                        }
                        # Add input to parent object
                        $Parents.($Param.Parent)[$Param.Name] = $Item.Value
                    } else {
                        # Add input to body output
                        $BodyOutput[$Param.Name] = $Item.Value
                    }
                }
            }
        }
        if ($Parents) {
            foreach ($Key in $Parents.Keys) {
                # Add value arrays with parents to body output
                $BodyOutput[$Key] = @( $Parents.$Key )
            }
        }
        if ($BodyOutput) {
            # Output body value
            $BodyOutput
        } elseif ($ByteArray) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] File: $Filename"

            # Output ByteArrayContent
            $ByteArray
        }
    }
}