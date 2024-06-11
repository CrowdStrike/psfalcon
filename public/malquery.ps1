function Get-FalconMalQuery {
<#
.SYNOPSIS
Verify the status and results of an asynchronous Falcon MalQuery request, such as a hunt or exact-search
.DESCRIPTION
Requires 'MalQuery: Read'.
.PARAMETER Id
Request identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMalQuery
#>
  [CmdletBinding(DefaultParameterSetName='/malquery/entities/requests/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/malquery/entities/requests/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
    if ($Request.resources) {
      $Request.resources
    } elseif ($Request.meta.reqid -and $Request.meta.reqtype -and $Request.meta.status) {
      $Request.meta | Select-Object reqid,reqtype,status
    } else {
      $Request
    }
  }
}
function Get-FalconMalQueryQuota {
<#
.SYNOPSIS
Retrieve Falcon MalQuery search and download quotas
.DESCRIPTION
Requires 'MalQuery: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMalQueryQuota
#>
  [CmdletBinding(DefaultParameterSetName='/malquery/aggregates/quotas/v1:get',SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
}
function Get-FalconMalQuerySample {
<#
.SYNOPSIS
Retrieve Falcon MalQuery indexed file metadata
.DESCRIPTION
Requires 'MalQuery: Read'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMalQuerySample
#>
  [CmdletBinding(DefaultParameterSetName='/malquery/entities/metadata/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/malquery/entities/metadata/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Group-FalconMalQuerySample {
<#
.SYNOPSIS
Schedule MalQuery samples for download
.DESCRIPTION
Requires 'MalQuery: Write'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Group-FalconMalQuerySample
#>
  [CmdletBinding(DefaultParameterSetName='/malquery/entities/samples-multidownload/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/malquery/entities/samples-multidownload/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('samples','sample','ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Invoke-FalconMalQuery {
<#
.SYNOPSIS
Initiate a Falcon MalQuery YARA hunt, exact search or fuzzy search
.DESCRIPTION
Requires 'MalQuery: Write'.
.PARAMETER YaraRule
Schedule a YARA-based search
.PARAMETER Type
Search pattern type
.PARAMETER Value
Search pattern value
.PARAMETER FilterFiletype
File type to include with the result
.PARAMETER FilterMeta
Subset of metadata fields to include in the result
.PARAMETER MinSize
Minimum file size specified in bytes or multiples of KB/MB/GB
.PARAMETER MaxSize
Maximum file size specified in bytes or multiples of KB/MB/GB
.PARAMETER MinDate
Limit results to files first seen after this date
.PARAMETER MaxDate
Limit results to files first seen before this date
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Fuzzy
Search MalQuery quickly but with more potential for false positives
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconMalQuery
#>
  [CmdletBinding(DefaultParameterSetName='/malquery/queries/exact-search/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Mandatory,Position=1)]
    [Alias('yara_rule')]
    [string]$YaraRule,
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Mandatory,Position=1)]
    [ValidateSet('hex','ascii','wide',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Mandatory,Position=2)]
    [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Mandatory,Position=2)]
    [string]$Value,
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=2)]
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=3)]
    [ValidateSet('cdf','cdfv2','cjava','dalvik','doc','docx','elf32','elf64','email','html','hwp',
      'java.arc','lnk','macho','pcap','pdf','pe32','pe64','perl','ppt','pptx','python','pythonc',
      'rtf','swf','text','xls','xlsx',IgnoreCase=$false)]
    [Alias('filter_filetypes','FilterFileTypes')]
    [string[]]$FilterFiletype,
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=3)]
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=4)]
    [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Position=3)]
    [ValidateSet('sha256','md5','type','size','first_seen','label','family',IgnoreCase=$false)]
    [Alias('filter_meta')]
    [string[]]$FilterMeta,
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=4)]
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=5)]
    [Alias('min_size')]
    [string]$MinSize,
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=5)]
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=6)]
    [Alias('max_size')]
    [string]$MaxSize,
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=6)]
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=7)]
    [ValidatePattern('^\d{4}/\d{2}/\d{2}$')]
    [Alias('min_date')]
    [string]$MinDate,
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=7)]
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=8)]
    [ValidatePattern('^\d{4}/\d{2}/\d{2}$')]
    [Alias('max_date')]
    [string]$MaxDate,
    [Parameter(ParameterSetName='/malquery/queries/hunt/v1:post',Position=8)]
    [Parameter(ParameterSetName='/malquery/queries/exact-search/v1:post',Position=9)]
    [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Position=4)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/malquery/combined/fuzzy-search/v1:post',Mandatory)]
    [switch]$Fuzzy
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('yara_rule','options'); patterns = @('type','value') }}
    }
    $Aliases = (Get-Command $MyInvocation.MyCommand.Name).Parameters.GetEnumerator().Where({
      $_.Value.Attributes.ParameterSetName -eq $PSCmdlet.ParameterSetName })
    $Options = @{}
    foreach ($Opt in @('FilterFiletype','FilterMeta','Limit','MaxDate','MaxSize','MinDate','MinSize')) {
      if ($PSBoundParameters.$Opt) {
        $Alias = $Aliases.Where({ $_.Key -eq $Opt }).Value.Aliases[0]
        $Key = if ($Alias) { $Alias } else { $Opt.ToLower() }
        $Options[$Key] = $PSBoundParameters.$Opt
        [void]$PSBoundParameters.Remove($Opt)
      }
    }
    if ($Options) { $PSBoundParameters['options'] = $Options }
  }
  process {
    $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
    if ($Request.meta.reqid -and $Request.meta.status) {
      $Request.meta | Select-Object reqid,status
    } else {
      $Request
    }
  }
}
function Receive-FalconMalQuerySample {
<#
.SYNOPSIS
Download a sample or sample archive from Falcon MalQuery [password: 'infected']
.DESCRIPTION
Requires 'MalQuery: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Sha256 hash value or MalQuery sample archive identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconMalQuerySample
#>
  [CmdletBinding(DefaultParameterSetName='/malquery/entities/download-files/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/malquery/entities/download-files/v1:get',Mandatory,Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/malquery/entities/download-files/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^([A-Fa-f0-9]{64}|\w{8}-\w{4}-\w{4}-\w{4}-\w{12})$')]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/malquery/entities/download-files/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = if ($PSBoundParameters.Id -match '^[A-Fa-f0-9]{64}$') {
        '/malquery/entities/download-files/v1:get'
      } else {
        '/malquery/entities/samples-fetch/v1:get'
      }
      Headers = if ($PSBoundParameters.Id -match '^[A-Fa-f0-9]{64}$') {
        @{ Accept = 'application/octet-stream' }
      } else {
        @{ Accept = 'application/zip' }
      }
    }
  }
  process {
    if ($Param.Headers.Accept -match 'zip$') {
      $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'zip'
    }
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Search-FalconMalQueryHash {
<#
.SYNOPSIS
Perform a simple Falcon MalQuery YARA Hunt for a Sha256 hash
.DESCRIPTION
Performs a YARA Hunt for the given hash, then checks every 5 seconds--for up to 60 seconds--for a result.

Requires 'MalQuery: Write'.
.PARAMETER Sha256
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Search-FalconMalQueryHash
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$Sha256
  )
  process {
    try {
      $Param = @{
        YaraRule = 'import "hash" rule SearchHash { condition: hash.sha256(0,filesize) == "' +
          $PSBoundParameters.Sha256 + '" }'
        FilterMeta = @('sha256','type','label','family')
      }
      $Request = Invoke-FalconMalQuery @Param
      if ($Request.reqid) {
        $Result = Get-FalconMalQuery -Id $Request.reqid
        if ($Result.status -eq 'inprogress') {
          do {
            Start-Sleep -Seconds 5
            $i += 5
            $Result = Get-FalconMalQuery -Id $Request.reqid
          } until (
            ($Result.status -ne 'inprogress') -or ($i -ge 60)
          )
        }
        $Result
      }
    } catch {
      $_
    }
  }
}