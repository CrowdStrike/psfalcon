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
            try {
                $HTML = ($Response.Result.Content).ReadAsStringAsync().Result
            }
            catch {
                $_
            }
        }
        elseif ($Response.Result.Content) {
            try {
                $Json = ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
            }
            catch {
                $_
            }
        }
        if ($Json) {
            Read-Meta -Object $Json -Endpoint $Endpoint -TypeName $Definition
            Write-Debug "[$($MyInvocation.MyCommand.Name)] `r`n$($Json | ConvertTo-Json -Depth 16)"
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
                    if ($Meta) {
                        ($Meta.PSObject.Properties.Name).foreach{
                            if ($_ -notmatch '(entity|pagination|powered_by|query_time|trace_id)' -and $Meta.$_) {
                                if (-not($MetaValues)) {
                                    $MetaValues = [PSCustomObject] @{}
                                }
                                $Name = if ($_ -eq 'writes') {
                                    $Meta.$_.PSObject.Properties.Name
                                }
                                else {
                                    $_
                                }
                                $Value = if ($Name -eq 'resources_affected') {
                                    $Meta.$_.PSObject.Properties.Value
                                }
                                else {
                                    $Meta.$_
                                }
                                $MetaValues.PSObject.Properties.Add((New-Object PSNoteProperty($Name,$Value)))
                            }
                        }
                        if ($MetaValues) {
                            $MetaValues
                        }
                    }
                }
                if ($Output) {
                    $Output
                }
            }
            elseif ($HTML) {
                $HTML
            }
            elseif ($Response.Result.Content) {
                ($Response.Result.Content).ReadAsStringAsync().Result
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