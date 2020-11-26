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
        $VerboseName = $MyInvocation.MyCommand.Name
        Write-Verbose ("[$($VerboseName)] $($StatusCode): $TypeName")
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
            if ($TypeName) {
                $Meta.PSObject.TypeNames.Insert(0,$TypeName)
            }
        }
        if ($Meta) {
            ($Meta.PSObject.Properties).foreach{
                Read-VerboseValue $_
            }
        }
    }
}