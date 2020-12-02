function Format-Result {
    <#
    .SYNOPSIS
        Formats a response from the Falcon API
    .PARAMETER RESPONSE
        Response object from a Falcon API request
    .PARAMETER ENDPOINT
        Falcon endpoint
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Response,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint
    )
    begin {
        $StatusCode = $Response.Result.StatusCode.GetHashCode()
        if ($StatusCode) {
            $Definition = $Falcon.Response($Endpoint, $StatusCode)
        }
        if ($Response.Result.Content -match '^<') {
            $HTML = ($Response.Result.Content).ReadAsStringAsync().Result
        }
        elseif ($Response.Result.Content) {
            $Json = ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
        }
        if ($Json) {
            Read-Meta -Object $Json -Endpoint $Endpoint -TypeName $Definition
        }
    }
    process {
        try {
            if ($Json) {
                $Populated = ($Json.PSObject.Properties | Where-Object { ($_.Name -ne 'meta') -and
                ($_.Name -ne 'errors') }).foreach{
                    if ($_.Value) {
                        $_.Name
                    }
                }
                ($Json.PSObject.Properties | Where-Object { ($_.Name -eq 'errors') }).foreach{
                    if ($_.Value) {
                        ($_.Value).foreach{
                            $PSCmdlet.WriteError(
                                [System.Management.Automation.ErrorRecord]::New(
                                    [Exception]::New("$($_.code): $($_.message)"),
                                    $Meta.trace_id,
                                    [System.Management.Automation.ErrorCategory]::NotSpecified,
                                    $Response.Result
                                )
                            )
                        }
                    }
                }
                $Output = if ($Populated.count -gt 1) {
                    if ($Populated -eq 'batch_id' -and 'resources') {
                        [PSCustomObject] @{
                            batch_id = $Json.batch_id
                            hosts = $Json.resources.PSObject.Properties.Value
                        }
                    }
                    else {
                        $Json
                    }
                }
                elseif ($Populated.count -eq 1) {
                    if ($Populated[0] -eq 'combined') {
                        $Json.combined.resources.PSObject.Properties.Value
                    }
                    else {
                        $Json.($Populated[0])
                    }
                }
                else {
                    if ($Meta.writes) {
                        $Meta.writes
                    }
                }
                if ($Output) {
                    $Output
                }
            }
            elseif ($HTML) {
                $HTML
            }
            else {
                $Response.Result.EnsureSuccessStatusCode()
            }
        }
        catch {
            $_
        }
    }
}