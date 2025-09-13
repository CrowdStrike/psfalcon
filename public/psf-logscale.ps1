function Register-FalconEventCollector {
<#
.SYNOPSIS
Define Falcon LogScale or Falcon NGSIEM ingestion endpoint and token for logging
.DESCRIPTION
Once configured, the Falcon LogScale or Falcon NGSIEM destination can be used by PSFalcon but the module will not
send events to until 'Enable' options are chosen. 'Remove-FalconEventCollector' can be used to remove a configured
destination and stop the transmission of events.
.PARAMETER Uri
Falcon LogScale cloud or Falcon NGSIEM HEC ingestion URI
.PARAMETER Token
Falcon LogScale or Falcon NGSIEM ingestion token
.PARAMETER Enable
Define events to send to the collector
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Register-FalconEventCollector
#>
  [CmdletBinding()]
  [OutputType([void])]
  param(
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,Position=1)]
    [System.Uri]$Uri,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^([a-fA-F0-9]{32}|[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})$')]
    [string]$Token,
    [Parameter(ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('responses','requests')]
    [string[]]$Enable
  )
  process {
    if (!$Script:Falcon.Api) { throw "[ApiClient] has not been initiated. Try 'Request-FalconToken'." }
    $Script:Falcon.Api.Collector = @{ Uri = $PSBoundParameters.Uri.ToString(); Token = $PSBoundParameters.Token }
    if ($Token -match '^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$') {
      $Script:Falcon.Api.Collector.Uri += 'api/v1/ingest/humio-structured/'
    }
    [string]$Message = "Added '$($Script:Falcon.Api.Collector.Uri)'"
    if ($PSBoundParameters.Enable) {
      $Script:Falcon.Api.Collector['Enable'] = $PSBoundParameters.Enable
      $Message += " for $(@($PSBoundParameters.Enable).foreach{ "'$_'" } -join ',')"
    }
    Write-Log 'Register-FalconEventCollector' $Message
  }
}
function Send-FalconEvent {
<#
.SYNOPSIS
Create Falcon LogScale or Falcon NGSIEM events from PSFalcon command results
.DESCRIPTION
Uses the pre-defined 'Path' and 'Token' values from 'Register-FalconEventCollector' to create events from the
output provided by a PSFalcon command.
.PARAMETER Object
PSFalcon command output
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconEvent
#>
  [CmdletBinding()]
  [OutputType([void])]
  param(
    [Parameter(Mandatory,ValueFromPipeline,Position=1)]
    [object]$Object
  )
  begin {
    $OriginalProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($Script:Falcon.Api.Collector.Token -and $Script:Falcon.Api.Collector.Token -match '^[a-fA-F0-9]{32}$') {
      # Force object into [PSCustomObject] type and send to Falcon NGSIEM
      [PSCustomObject]$Object = if ($Object -is [string]) { @{ string = $Object } } else { $Object }
      Set-Property $Object '@timestamp' ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
      Set-Property $Object '@sourcetype' $Script:Falcon.Api.UserAgent
      $Param = @{
        Uri = $Script:Falcon.Api.Collector.Uri
        Method = 'POST'
        Headers = @{
          Authorization = @('Bearer',$Script:Falcon.Api.Collector.Token) -join ' '
          ContentType = 'application/json'
        }
        Body = @{ event = $Object } | ConvertTo-Json -Depth 32
      }
      try { [void](Invoke-WebRequest @Param -UseBasicParsing) } catch { Write-Error $_ }
    } else {
      if ($Object) { @($Object).foreach{ $List.Add($_) }}
    }
  }
  end {
    if (!$Script:Falcon.Api.Collector.Uri -or !$Script:Falcon.Api.Collector.Token) {
      throw "Falcon LogScale destination has not been configured. Try 'Register-FalconEventCollector'."
    } elseif ($List) {
      # Send events to Falcon LogScale environment
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
Display existing Falcon LogScale ingestion endpoint and token
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Show-FalconEventCollector
#>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param()
  process { if ($Script:Falcon.Api.Collector) { [PSCustomObject]$Script:Falcon.Api.Collector }}
}
function Unregister-FalconEventCollector {
<#
.SYNOPSIS
Remove an existing Falcon LogScale ingestion endpoint and token
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Unregister-FalconEventCollector
#>
  [CmdletBinding()]
  param()
  process {
    if ($Script:Falcon.Api.Collector) {
      Write-Log 'Unregister-FalconEventCollector' "Removed '$($Script:Falcon.Api.Collector.Uri)'"
      $Script:Falcon.Api.Collector = @{}
    }
  }
}
$Register = @{
  # Add default Humio cloud addresses for autocompletion
  CommandName = 'Register-FalconEventCollector'
  ParameterName = 'Uri'
  ScriptBlock = {
    param($CommandName,$ParameterName,$WordToComplete,$CommandAst,$FakeBoundParameters)
    $PublicCloud = @('https://cloud.community.humio.com/','https://cloud.humio.com/',
      'https://cloud.us.humio.com/')
    $Match = $PublicCloud | Where-Object { $_ -like "$WordToComplete*" }
    $Match | ForEach-Object {
      New-Object -Type System.Management.Automation.CompletionResult -ArgumentList $_,
      $_,
      'ParameterValue',
      $_
    }
  }
}
Register-ArgumentCompleter @Register