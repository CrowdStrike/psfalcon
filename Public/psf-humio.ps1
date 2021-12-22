function Register-HumioEventCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [Alias('humio_path')]
        [System.Uri] $Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Alias('humio_token')]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Token
    )
    begin {
        if (!$Script:Falcon.Hostname) {
            Request-FalconToken
        }
    }
    process {
        @('Path', 'Token').foreach{
            $Script:Falcon["Humio$($_)"] = $PSBoundParameters.$_
        }
    }
}
function Remove-HumioEventCollector {
    [CmdletBinding()]
    param()
    process {
        @('Path', 'Token').foreach{
            if ($Script:Falcon -and $Script:Falcon."Humio$($_)") {
                $Script:Falcon.PSObject.Properties.Remove("Humio$($_)")
            }
        }
    }
}
function Show-HumioEventCollector {
    [CmdletBinding()]
    param()
    process {
        if ($Script:Falcon) {
            [PSCustomObject] @{
                HumioUrl   = if ($Script:Falcon.HumioPath) {
                    $Script:Falcon.HumioPath
                } else {
                    $null
                }
                HumioToken = if ($Script:Falcon.HumioToken) {
                    $Script:Falcon.HumioToken
                } else {
                    $null
                }
            }
        } else {
            Write-Error "No authorization token available. Try 'Request-FalconToken'."
        }
    }
}