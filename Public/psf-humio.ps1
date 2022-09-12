function Register-FalconEventCollector {
<#
.SYNOPSIS
Define Humio ingestion endpoint and token for logging
.DESCRIPTION
Once configured, the Humio destination can be used by PSFalcon but the module will not send events to Humio
until 'Enable' options are chosen. 'Remove-FalconEventCollector' can be used to remove a configured destination
and stop the transmission of events.
.PARAMETER Uri
Humio cloud
.PARAMETER Token
Humio ingestion token
.PARAMETER Enable
Define events to send to the collector
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Third-party-ingestion
#>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,Position=1)]
        [System.Uri]$Uri,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [string]$Token,
        [Parameter(ValueFromPipelineByPropertyName,Position=3)]
        [ValidateSet('responses','requests')]
        [string[]]$Enable
    )
    process {
        if (!$Script:Falcon.Api) { throw "[ApiClient] has not been initiated. Try 'Request-FalconToken'." }
        $Script:Falcon.Api.Collector = @{
            Uri = $PSBoundParameters.Uri.ToString() + 'api/v1/ingest/humio-structured/'
            Token = $PSBoundParameters.Token
        }
        [string]$Message = "Added '$($Script:Falcon.Api.Collector.Uri)'"
        if ($PSBoundParameters.Enable) {
            $Script:Falcon.Api.Collector['Enable'] = $PSBoundParameters.Enable
            $Message += " for $(@($PSBoundParameters.Enable).foreach{ "'$_'" } -join ',')"
        }
        Write-Verbose "[Register-FalconEventCollector] $Message."
    }
}
function Send-FalconEvent {
<#
.SYNOPSIS
Create Humio events from PSFalcon command results
.DESCRIPTION
Uses the pre-defined 'Path' and 'Token' values from 'Register-FalconEventCollector' to create events from the
output provided by a PSFalcon command.
.PARAMETER Object
PSFalcon command output
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Third-party-ingestion
#>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory,ValueFromPipeline,Position=1)]
        [System.Object]$Object
    )
    begin {
        $OriginalProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        [System.Collections.Generic.List[object]]$List = @()
    }
    process { if ($Object) { @($Object).foreach{ $List.Add($_) }}}
    end {
        if (!$Script:Falcon.Api.Collector.Uri -or !$Script:Falcon.Api.Collector.Token) {
            throw "Humio destination has not been configured. Try 'Register-FalconEventCollector'."
        } elseif ($List) {
            [object[]]$Events = @($List).foreach{
                $Item = @{ timestamp = Get-Date -Format o; attributes = @{}}
                if ($_ -is [PSCustomObject]) {
                    @($_.PSObject.Properties | Where-Object { $_.Name -notmatch '\.' }).foreach{
                        $Item.attributes[$_.Name] = $_.Value
                    }
                } elseif ($_ -is [string]) {
                    $Item.attributes['id'] = $_
                }
                $Item
            }
            $Param = @{
                Uri = $Script:Falcon.Api.Collector.Uri
                Method = 'post'
                Headers = @{
                    Authorization = @('Bearer',$Script:Falcon.Api.Collector.Token) -join ' '
                    ContentType = 'application/json'
                }
                Body = ConvertTo-Json @(
                    @{
                        tags = @{ host = [System.Net.Dns]::GetHostname(); source = (Show-FalconModule).UserAgent }
                        events = $Events
                    }
                ) -Depth 8 -Compress
            }
            [void](Invoke-WebRequest @Param -UseBasicParsing)
        }
        $ProgressPreference = $OriginalProgress
    }
}
function Show-FalconEventCollector {
<#
.SYNOPSIS
Display existing Humio ingestion endpoint and token
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Third-party-ingestion
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    process {
        if ($Script:Falcon.Api.Collector) { [PSCustomObject]$Script:Falcon.Api.Collector }
    }
}
function Unregister-FalconEventCollector {
<#
.SYNOPSIS
Remove an existing Humio ingestion endpoint and token
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Third-party-ingestion
#>
    [CmdletBinding()]
    param()
    process {
        if ($Script:Falcon.Api.Collector) {
            Write-Verbose "[Unregister-FalconEventCollector] Removed '$($Script:Falcon.Api.Collector.Uri)'."
            $Script:Falcon.Api.Collector = @{}
        }
    }
}
$Register = @{
    CommandName = 'Register-FalconEventCollector'
    ParameterName = 'Uri'
    ScriptBlock = {
        param($CommandName,$ParameterName,$WordToComplete,$CommandAst,$FakeBoundParameters)
        $PublicClouds = @('https://cloud.community.humio.com/','https://cloud.humio.com/',
            'https://cloud.us.humio.com/')
        $Match = $PublicClouds | Where-Object { $_ -like "$WordToComplete*" }
        $Match | ForEach-Object {
            New-Object -Type System.Management.Automation.CompletionResult -ArgumentList $_,
            $_,
            'ParameterValue',
            $_
        }
    }
}
Register-ArgumentCompleter @Register