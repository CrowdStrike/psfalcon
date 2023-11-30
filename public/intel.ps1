function Get-FalconActor {
<#
.SYNOPSIS
Search for threat actors
.DESCRIPTION
Requires 'Actors (Falcon Intelligence): Read'.
.PARAMETER Id
Threat actor identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Field
Specific fields, or a predefined collection name surrounded by two underscores [default: __basic__]
.PARAMETER Include
Include additional information
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconActor
#>
  [CmdletBinding(DefaultParameterSetName='/intel/queries/actors/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/actors/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=1)]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=2)]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=3)]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=3)]
    [ValidateSet('name|asc','name|desc','target_countries|asc','target_countries|desc',
      'target_industries|asc','target_industries|desc','type|asc','type|desc','created_date|asc',
      'created_date|desc','last_activity_date|asc','last_activity_date|desc','last_modified_date|asc',
      'last_modified_date|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=4)]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/intel/entities/actors/v1:get',Position=2)]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=5)]
    [Alias('Fields')]
    [string[]]$Field,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get',Position=5)]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Position=6)]
    [ValidateSet('tactic_and_technique',IgnoreCase=$false)]
    [string]$Include,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
    [Parameter(ParameterSetName='/intel/combined/actors/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/intel/queries/actors/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
    if ($Include) {
      $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
      if (!$Request.slug) { $Request = $Request | & $MyInvocation.MyCommand.Name | Select-Object id,slug }
      @($Request).foreach{
        $Attck = try { [string[]](Get-FalconAttck -Slug $_.slug -EA 0) } catch { [string[]]@() }
        if ($Attck -and $PSBoundParameters.Detailed) {
          $Attck = try { [object[]]($Attck | Get-FalconAttck -EA 0) } catch { [object[]]@() }
        }
        $_.PSObject.Properties.Add((New-Object PSNoteProperty('tactic_and_technique',$Attck)))
      }
      $Request
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconAttck {
<#
.SYNOPSIS
Search for Mitre ATT&CK tactic and technique information related to specific actors
.DESCRIPTION
Requires 'Actors (Falcon Intelligence): Read'.
.PARAMETER Id
Tactic and technique identifier, by actor
.PARAMETER Slug
Actor identifier ('slug')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconAttck
#>
  [CmdletBinding(DefaultParameterSetName='/intel/queries/mitre/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/mitre/v1:post',Mandatory,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/intel/queries/mitre/v1:get',Mandatory,Position=1)]
    [Alias('actor_id')]
    [string]$Slug
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } else {
      $PSBoundParameters['id'] = $PSBoundParameters.Slug
      [void]$PSBoundParameters.Remove('Slug')
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconCve {
<#
.SYNOPSIS
Search for Falcon Intelligence CVE reports
.DESCRIPTION
Requires 'Vulnerabilities (Falcon Intelligence): Read'.
.PARAMETER Id
CVE identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCve
#>
  [CmdletBinding(DefaultParameterSetName='/intel/queries/vulnerabilities/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/vulnerabilities/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get',Position=4)]
    [int]$Limit,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/intel/queries/vulnerabilities/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
  [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconIndicator {
<#
.SYNOPSIS
Search for intelligence indicators
.DESCRIPTION
Requires 'Indicators (Falcon Intelligence): Read'.
.PARAMETER Id
Indicator identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER IncludeDeleted
Include previously deleted indicators
.PARAMETER IncludeRelation
Include related indicators
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIndicator
#>
  [CmdletBinding(DefaultParameterSetName='/intel/queries/indicators/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/indicators/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=1)]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=2)]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=3)]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=3)]
    [ValidateSet('id|asc','id|desc','indicator|asc','indicator|desc','type|asc','type|desc',
      'published_date|asc','published_date|desc','last_updated|asc','last_updated|desc',
      '_marker|asc','_marker|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=4)]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=5)]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=5)]
    [Alias('include_deleted')]
    [boolean]$IncludeDeleted,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get',Position=6)]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Position=6)]
    [Alias('include_relations')]
    [boolean]$IncludeRelation,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
    [Parameter(ParameterSetName='/intel/combined/indicators/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/intel/queries/indicators/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconIntel {
<#
.SYNOPSIS
Search for intelligence reports
.DESCRIPTION
Requires 'Reports (Falcon Intelligence): Read'.
.PARAMETER Id
Report identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Field
Specific fields, or a predefined collection name surrounded by two underscores [default: __basic__]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIntel
#>
  [CmdletBinding(DefaultParameterSetName='/intel/queries/reports/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/reports/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=1)]
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=2)]
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=3)]
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=3)]
    [ValidateSet('name|asc','name|desc','target_countries|asc','target_countries|desc',
      'target_industries|asc','target_industries|desc','type|asc','type|desc','created_date|asc',
      'created_date|desc','last_modified_date|asc','last_modified_date|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/intel/queries/reports/v1:get',Position=4)]
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/intel/entities/reports/v1:get',Position=2)]
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Position=5)]
    [Alias('Fields')]
    [string[]]$Field,
    [Parameter(ParameterSetName='/intel/queries/reports/v1:get')]
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/intel/entities/reports/v1:get')]
    [Parameter(ParameterSetName='/intel/combined/reports/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/intel/entities/reports/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconRule {
<#
.SYNOPSIS
Search for Falcon Intelligence rulesets
.DESCRIPTION
Requires 'Rules (Falcon Intelligence): Read'.
.PARAMETER Id
Ruleset identifier
.PARAMETER Type
Ruleset type
.PARAMETER Name
Ruleset name
.PARAMETER Description
Ruleset description
.PARAMETER Tag
Ruleset tag
.PARAMETER MinCreatedDate
Filter results to those created on or after a date
.PARAMETER MaxCreatedDate
Filter results to those created on or before a date
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconRule
#>
  [CmdletBinding(DefaultParameterSetName='/intel/queries/rules/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/rules/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^\d{4,}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Mandatory,Position=1)]
    [ValidateSet('snort-suricata-master','snort-suricata-update','snort-suricata-changelog','yara-master',
      'yara-update','yara-changelog','common-event-format','netwitness',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=2)]
    [string[]]$Name,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=3)]
    [string[]]$Description,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=4)]
    [Alias('tags')]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=5)]
    [Alias('min_created_date')]
    [int32]$MinCreatedDate,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=6)]
    [Alias('max_created_date')]
    [string]$MaxCreatedDate,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=7)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=8)]
    [string]$Sort,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get',Position=9)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/intel/queries/rules/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Receive-FalconAttck {
<#
.SYNOPSIS
Download Mitre ATT&CK information for an actor
.DESCRIPTION
Requires 'Actors (Falcon Intelligence): Read'.
.PARAMETER Path
Destination path
.PARAMETER Slug
Actor identifier ('slug')
.PARAMETER Format
Export format
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconAttck
#>
  [CmdletBinding(DefaultParameterSetName='/intel/entities/mitre-reports/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/mitre-reports/v1:get',Mandatory,Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/intel/entities/mitre-reports/v1:get',Mandatory,Position=2)]
    [Alias('actor_id')]
    [string]$Slug,
    [Parameter(ParameterSetName='/intel/entities/mitre-reports/v1:get',Mandatory,Position=3)]
    [ValidateSet('csv','json',IgnoreCase=$false)]
    [string]$Format,
    [Parameter(ParameterSetName='/intel/entities/mitre-reports/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path $Format
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
function Receive-FalconIntel {
<#
.SYNOPSIS
Download an intelligence report
.DESCRIPTION
Requires 'Reports (Falcon Intelligence): Read'.
.PARAMETER Path
Destination path [default: <slug>.pdf]
.PARAMETER Id
Report identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconIntel
#>
  [CmdletBinding(DefaultParameterSetName='/intel/entities/report-files/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/report-files/v1:get',ValueFromPipelineByPropertyName,
      Position=1)]
    [Alias('slug')]
    [string]$Path,
    [Parameter(ParameterSetName='/intel/entities/report-files/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^\d{2,}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/intel/entities/report-files/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/pdf' }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'pdf'
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
function Receive-FalconRule {
<#
.SYNOPSIS
Download the most recent ruleset, or a specific ruleset
.DESCRIPTION
Requires 'Rules (Falcon Intelligence): Read'.
.PARAMETER Type
Ruleset type, used to retrieve the latest ruleset
.PARAMETER IfNoneMatch
Download the latest rule set only if it doesn't a matching 'tags' value
.PARAMETER IfModifiedSince
Restrict results to those modified after a provided date (HTTP, ANSIC or RFC850 format)
.PARAMETER Path
Destination path
.PARAMETER Id
Ruleset identifier, used for a specific ruleset
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconRule
#>
  [CmdletBinding(DefaultParameterSetName='/intel/entities/rules-files/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/intel/entities/rules-latest-files/v1:get',Mandatory,Position=1)]
    [ValidateSet('common-event-format','netwitness','snort-suricata-changelog','snort-suricata-master',
      'snort-suricata-update','yara-changelog','yara-master','yara-update',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/intel/entities/rules-latest-files/v1:get',Position=2)]
    [Alias('If-None-Match')]
    [string]$IfNoneMatch,
    [Parameter(ParameterSetName='/intel/entities/rules-latest-files/v1:get',Position=3)]
    [Alias('If-Modified-Since')]
    [string]$IfModifiedSince,
    [Parameter(ParameterSetName='/intel/entities/rules-files/v1:get',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/intel/entities/rules-latest-files/v1:get',Mandatory,Position=4)]
    [ValidatePattern('\.(gz|gzip|zip)$')]
    [string]$Path,
    [Parameter(ParameterSetName='/intel/entities/rules-files/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=2)]
    [int32]$Id,
    [Parameter(ParameterSetName='/intel/entities/rules-files/v1:get')]
    [switch]$Force
  )
  begin {
    $Accept = if ($PSBoundParameters.Path -match '\.(gz|gzip)$') {
      $PSBoundParameters['format'] = 'gzip'
      'application/gzip'
    } else {
      'application/zip'
    }
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = $Accept }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
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