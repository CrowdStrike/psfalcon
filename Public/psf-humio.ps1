function Register-FalconEventCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [System.Uri] $Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Token,

        [Parameter(Mandatory = $true, ValueFromPipeLineByPropertyName = $true, Position = 3)]
        [ValidateSet('library','responses','requests')]
        [array] $Enabled
    )
    process {
        if (!$Script:Falcon.Api) {
            throw "[ApiClient] has not been initiated. Use 'Request-FalconToken'."
        }
        $Script:Falcon.Api.Collector = @{
            Path    = $PSBoundParameters.Path
            Token   = $PSBoundParameters.Token
            Enabled = $PSBoundParameters.Enabled
        }
        Write-Verbose "[Register-FalconEventCollector] Added '$($Script:Falcon.Api.Collector.Path)' for $(
            @($PSBoundParameters.Enabled).foreach{ "'$_'" } -join ', ')."
    }
}
function Show-FalconEventCollector {
    [CmdletBinding()]
    param()
    process {
        if (!$Script:Falcon.Api.Collector) {
            throw "[ApiClient] has not been initiated. Use 'Request-FalconToken'."
        }
        [PSCustomObject] @{
            Path    = $Script:Falcon.Api.Collector.Path
            Token   = $Script:Falcon.Api.Collector.Token
            Enabled = $Script:Falcon.Api.Collector.Enabled
        }
    }
}
function Unregister-FalconEventCollector {
    [CmdletBinding()]
    param()
    process {
        if ($Script:Falcon.Api.Collector) {
            Write-Verbose "[Unregister-FalconEventCollector] Removed '$($Script:Falcon.Api.Collector.Path)'."
            $Script:Falcon.Api.Collector = @{}
        }
    }
}
