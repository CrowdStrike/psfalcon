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
    process {
        $Script:Humio = @{
            Path  = $PSBoundParameters.Path
            Token = $PSBoundParameters.Token
        }
        if ($Script:Falcon -and -not $Script:Falcon.Request) {
            $Script:Falcon['Request'] = @{}
        }
    }
}
function Remove-HumioEventCollector {
    [CmdletBinding()]
    param()
    process {
        if (Get-Variable -Name Humio -Scope Script -ErrorAction SilentlyContinue) {
            Remove-Variable -Name Humio -Scope Script
        }
    }
}
function Show-HumioEventCollector {
    [CmdletBinding()]
    param()
    process {
        [PSCustomObject] @{
            HumioPath  = if ($Script:Humio.Path) {
                $Script:Humio.Path
            } else {
                $null
            }
            HumioToken = if ($Script:Humio.Token) {
                $Script:Humio.Token
            } else {
                $null
            }
        }
    }
}