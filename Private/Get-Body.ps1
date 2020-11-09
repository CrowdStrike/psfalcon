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
        [Parameter(Mandatory = $true)]
        [object] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            Add-Type -AssemblyName System.Net.Http
        }
    }
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = if ($Endpoint.Parameters.Dynamic -contains $Item.Name) {
                $Endpoint.Parameters | Where-Object Dynamic -EQ $Item.Name
            }
            else {
                $Falcon.Endpoint('private/SharedParameters').Parameters | Where-Object Dynamic -EQ $Item.Name
            }
            if ($Param.In -match 'body') {
                if ($Param.Name -eq 'body') {
                    $Filename = $Item.Value
                    $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
                        Get-Content $Item.Value -AsByteStream
                    }
                    else {
                        Get-Content $Item.Value -Encoding Byte -Raw
                    }
                    $ByteArray = [System.Net.Http.ByteArrayContent]::New($ByteStream)
                    $ByteArray.Headers.Add('Content-Type', $Endpoint.Headers.ContentType)
                }
                else {
                    if (-not($BodyOutput)) {
                        $BodyOutput = @{ }
                    }
                    if ($Param.Parent) {
                        if (-not($Parents)) {
                            $Parents = @{ }
                        }
                        if (-not($Parents.($Param.Parent))) {
                            $Parents[$Param.Parent] = @{ }
                        }
                        $Parents.($Param.Parent)[$Param.Name] = $Item.Value
                    }
                    else {
                        $BodyOutput[$Param.Name] = $Item.Value
                    }
                }
            }
        }
        if ($Parents) {
            foreach ($Key in $Parents.Keys) {
                $BodyOutput[$Key] = @( $Parents.$Key )
            }
        }
        if ($BodyOutput) {
            $BodyOutput
        }
        elseif ($ByteArray) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] File: $Filename"
            $ByteArray
        }
    }
}