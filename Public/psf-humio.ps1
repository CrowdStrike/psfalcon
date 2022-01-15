function Register-FalconEventCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [System.Uri] $Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Token,

        [Parameter(ValueFromPipeLineByPropertyName = $true, Position = 3)]
        [ValidateSet('library','responses','requests')]
        [array] $Enabled
    )
    process {
        if (!$Script:Falcon.Api) {
            throw "[ApiClient] has not been initiated. Try 'Request-FalconToken'."
        }
        $Script:Falcon.Api.Collector = @{
            Path    = $PSBoundParameters.Path
            Token   = $PSBoundParameters.Token
        }
        $Message = "[Register-FalconEventCollector] Added '$($Script:Falcon.Api.Collector.Path)'"
        if ($PSBoundParameters.Enabled) {
            $Script:Falcon.Api.Collector['Enabled'] = $PSBoundParameters.Enabled
            $Message += " for $(@($PSBoundParameters.Enabled).foreach{ "'$_'" } -join ', ')"
        }
        Write-Verbose "$Message."
    }
}
function Send-FalconEvent {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [object] $Object
    )
    begin {
        $OriginalProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
    }
    process {
        if (!$Script:Falcon.Api.Collector.Path -or !$Script:Falcon.Api.Collector.Token) {
            throw "Humio destination has not been configured. Try 'Register-FalconEventCollector'."
        }
        [array] $Events = $PSBoundParameters.Object | ForEach-Object {
            $Item = @{
                timestamp = Get-Date -Format o
                attributes = @{}
            }
            if ($_ -is [System.Management.Automation.PSCustomObject]) {
                $_.PSObject.Properties | Where-Object { $_.Name -notmatch '\.' } | ForEach-Object {
                    $Item.attributes[$_.Name] = $_.Value
                }
            } elseif ($_ -is [string]) {
                $Item.attributes['id'] = $_
            }
            $Item
        }
        $Param = @{
            Uri     = $Script:Falcon.Api.Collector.Path
            Method  = 'post'
            Headers = @{
                Authorization = @('Bearer', $Script:Falcon.Api.Collector.Token) -join ' '
                ContentType   = 'application/json'
            }
            Body    = ConvertTo-Json -InputObject @(
                @{
                    tags   = @{
                        host   = [System.Net.Dns]::GetHostname()
                        source = (Show-FalconModule).UserAgent
                    }
                    events = $Events
                }
            ) -Depth 8 -Compress
        }
        [void] (Invoke-WebRequest @Param -UseBasicParsing)
    }
    end {
        $ProgressPreference = $OriginalProgress
    }
}
function Show-FalconEventCollector {
    [CmdletBinding()]
    param()
    process {
        if (!$Script:Falcon.Api.Collector) {
            throw "[ApiClient] has not been initiated. Try 'Request-FalconToken'."
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
