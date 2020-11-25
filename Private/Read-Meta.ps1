function Read-Meta {
    <#
    .SYNOPSIS
        Outputs verbose "meta" information and creates $Meta for loop processing
    .PARAMETER OBJECT
        Object from a Falcon API request
    .PARAMETER ENDPOINT
        Falcon endpoint
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Object,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint
    )
    begin {
        $VerboseName = $MyInvocation.MyCommand.Name
        function Read-VerboseValue ($Property) {
            if ($_.Value -is [PSCustomObject]) {
                ($_.Value.PSObject.Properties).foreach{
                    Read-VerboseValue $_
                }
            }
            else {
                Write-Verbose "[$($VerboseName)] $($_.Name): $($_.Value)"
            }
        }
    }
    process {
        if ($Object.meta) {
            $Script:Meta = $Object.meta
        }
        if ($Meta) {
            ($Meta.PSObject.Properties).foreach{
                Read-VerboseValue $_
            }
        }
    }
}