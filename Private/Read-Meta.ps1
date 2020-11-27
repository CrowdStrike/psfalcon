function Read-Meta {
    <#
    .SYNOPSIS
        Outputs verbose 'meta' information and creates $Meta for loop processing
    .PARAMETER OBJECT
        Object from a Falcon API request
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER TYPENAME
        Optional 'meta' object typename, sourced from API response code/definition
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Object,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint,

        [Parameter()]
        [string] $TypeName
    )
    begin {
        function Read-CountValue ($Property) {
            if ($_.Value -is [PSCustomObject]) {
                ($_.Value.PSObject.Properties).foreach{
                    Read-CountValue $_
                }
            }
            elseif ($_.Name -match '(after|offset|total)') {
                $Value = if (($_.Value -is [string]) -and ($_.Value.Length -gt 7)) {
                    "$($_.Value.Substring(0,6))..."
                }
                else {
                    $_.Value
                }
                "$($_.Name): $($Value)"
            }
        }
    }
    process {
        $ResponseInfo = "$($StatusCode): $TypeName"
        if ($Object.meta) {
            $Script:Meta = $Object.meta
            if ($TypeName) {
                $Meta.PSObject.TypeNames.Insert(0,$TypeName)
            }
        }
        if ($Meta) {
            if ($Meta.trace_id) {
                $ResponseInfo += ", trace_id: $($Meta.trace_id)"
            }
            $CountInfo = (($Meta.PSObject.Properties).foreach{
                Read-CountValue $_
            }) -join ', '
        }
        @($ResponseInfo, $CountInfo) | ForEach-Object {
            if ($_) {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] $_"
            }
        }
    }
}