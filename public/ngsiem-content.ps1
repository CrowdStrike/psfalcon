function Write-NgsContent {
  param(
    [string]$Command,
    [string]$Endpoint,
    [object]$UserInput,
    [string]$Property
  )
  begin {
    # Capture 'Detailed' and 'SearchDomain' values
    $Detailed = $UserInput.Detailed
    $Domain = $UserInput.Domain
    $Repository = $UserInput.Repository
    [void]$UserInput.Remove('Detailed')
  }
  process {
    Invoke-Falcon -Command $Command -Endpoint $Endpoint -UserInput $UserInput | ForEach-Object {
      if ($Endpoint -match '/entities/') {
        $_
      } else {
        # Re-submit result for 'Detailed' or output object with 'id' and 'search_domain' or 'repository'
        $Param = if ($Domain) {
          @{ $Property = $_; search_domain = $Domain }
        } else {
          @{ $Property = $_; repository = $Repository }
        }
        if ($Detailed -eq $true) { & $Command @Param } else { [PSCustomObject]$Param }
      }
    }
  }
}
function Edit-FalconNgsParser {
<#
.SYNOPSIS
Modify Falcon NGSIEM parsers
.DESCRIPTION
Requires 'NGSIEM Parsers: Write'.
.PARAMETER Id
Parser identifier
.PARAMETER Repository
Repository name
.PARAMETER Script
Parser script to transform input into events
.PARAMETER TestCase
An example event and output parameters to use for analysis
.PARAMETER FieldToRemove
Event fields to remove before parsing
.PARAMETER FieldToTag
Event fields to tag during parsing
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsParser
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/parsers/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('parsers-repository',IgnoreCase=$false)]
    [string]$Repository,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [string]$Script,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('test_cases')]
    [object[]]$TestCase,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [Alias('fields_to_be_removed_before_parsing')]
    [string[]]$FieldToRemoveParsing,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('fields_to_tag')]
    [string[]]$FieldToTag

  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('fields_to_be_removed_before_parsing','fields_to_tag','id','repository','script','test_cases')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconNgsDashboard {
<#
.SYNOPSIS
Search for Falcon NGSIEM dashboards
.DESCRIPTION
Requires 'NGSIEM Dashboards: Read'.
.PARAMETER Id
Dashboard identifier
.PARAMETER Domain
Repository or view to search
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Limit
Maximum number of results per request [default: 50]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsDashboard
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/queries/dashboards/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','dashboards','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get',Position=3)]
    [string]$Limit,
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','search_domain') }
    }
  }
  process { Write-NgsContent @Param -UserInput $PSBoundParameters -Property id }
}
function Get-FalconNgsLookupFile {
<#
.SYNOPSIS
Search for Falcon NGSIEM lookup files
.DESCRIPTION
Requires 'NGSIEM Lookup Files: Read'.
.PARAMETER Domain
Repository or view to search
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Limit
Maximum number of results per request [default: 50]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get',Mandatory,Position=1)]
    [ValidateSet('all','dashboards','falcon','parsers-repository','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get',Position=3)]
    [string]$Limit,
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','limit','offset','search_domain') }
    }
  }
  process { Write-NgsContent @Param -UserInput $PSBoundParameters -Property filename }
}
function Get-FalconNgsParser {
<#
.SYNOPSIS
Search for Falcon NGSIEM parsers
.DESCRIPTION
Requires 'NGSIEM Parsers: Read'.
.PARAMETER Id
Parser identifier
.PARAMETER Repository
Repository to search
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Limit
Maximum number of results per request [default: 50]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsParser
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/queries/parsers/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('parsers-repository',IgnoreCase=$false)]
    [string]$Repository,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get',Position=3)]
    [string]$Limit,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','repository') }
    }
  }
  process { Write-NgsContent @Param -UserInput $PSBoundParameters -Property id }
}
function Get-FalconNgsSavedQuery {
<#
.SYNOPSIS
Search for Falcon NGSIEM saved queries
.DESCRIPTION
Requires 'NGSIEM Saved Queries: Read'.
.PARAMETER Id
Saved query identifier
.PARAMETER Domain
Repository or view
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Limit
Maximum number of results per request [default: 50]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsSavedQuery
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/queries/savedqueries/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/queries/savedqueries/v1:get',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','dashboards','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/queries/savedqueries/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ngsiem-content/queries/savedqueries/v1:get',Position=3)]
    [string]$Limit,
    [Parameter(ParameterSetName='/ngsiem-content/queries/savedqueries/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/ngsiem-content/queries/savedqueries/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/ngsiem-content/queries/savedqueries/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ngsiem-content/queries/savedqueries/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','search_domain') }
    }
  }
  process { Write-NgsContent @Param -UserInput $PSBoundParameters -Property id }
}
function New-FalconNgsParser {
<#
.SYNOPSIS
Create a Falcon NGSIEM parser
.DESCRIPTION
Requires 'NGSIEM Parsers: Write'.
.PARAMETER Name
Parser name
.PARAMETER Repository
Repository name
.PARAMETER Script
Parser script to transform input into events
.PARAMETER TestCase
An example event and output parameters to use for analysis
.PARAMETER FieldToRemove
Event fields to remove before parsing
.PARAMETER FieldToTag
Event fields to tag during parsing
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconNgsParser
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/parsers/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('parsers-repository',IgnoreCase=$false)]
    [string]$Repository,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [string]$Script,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('test_cases')]
    [object[]]$TestCase,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [Alias('fields_to_be_removed_before_parsing')]
    [string[]]$FieldToRemove,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:post',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('fields_to_tag')]
    [string[]]$FieldToTag
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('fields_to_be_removed_before_parsing','fields_to_tag','name','repository','script','test_cases')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Receive-FalconNgsDashboard {
<#
.SYNOPSIS
Download a Falcon NGSIEM dashboard YAML template
.DESCRIPTION
Requires 'NGSIEM Dashboards: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Dashboard identifier
.PARAMETER Domain
Repository or view
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconNgsDashboard
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get',Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('all','dashboards','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get')]
    [switch]$Force
  )
  process {
    if (!$PSBoundParameters.Path) {
      # When 'Path' is not specified, use a combination of 'dashboard', 'search_domain', and 'id'
      $PSBoundParameters['Path'] = Join-Path (Get-Location).Path (('dashboard',$PSBoundParameters.Domain,
        $PSBoundParameters.Id -join '_'),'yaml' -join '.')
    }
    $Request = Get-FalconNgsDashboard -Id $PSBoundParameters.Id -Domain $PSBoundParameters.Domain
    if ($Request) {
      $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'yaml'
      $OutPath = Test-OutFile $PSBoundParameters.Path
      if ($OutPath.Category -eq 'ObjectNotFound') {
        Write-Error @OutPath
      } elseif ($PSBoundParameters.Path) {
        if ($OutPath.Category -eq 'WriteError' -and !$Force) {
          Write-Error @OutPath
        } elseif ($Request.yaml_template) {
          $OutParam = @{
            InputObject = $Request.yaml_template
            FilePath = $PSBoundParameters.Path
            Encoding = 'UTF8'
          }
          if ($PSBoundParameters.Force) { $OutParam['Force'] = $true }
          Out-File @OutParam
        }
      }
    }
  }
  end {
    if ($Request -and $OutParam -and (Test-Path $OutParam.FilePath)) {
      Get-ChildItem $OutParam.FilePath | Select-Object FullName,Length,LastWriteTime
    }
  }
}
function Receive-FalconNgsLookupFile {
<#
.SYNOPSIS
Download a Falcon NGSIEM lookup file
.DESCRIPTION
Requires 'NGSIEM Lookup Files: Read'.
.PARAMETER Path
Destination path [default: .\<filename>.csv]
.PARAMETER Filename
Lookup file name
.PARAMETER Domain
Repository or view to search
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconNgsLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/lookupfiles/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:get',Position=1)]
    [ValidatePattern('\.gzip$')]
    [string]$Path,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [string]$Filename,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('all','dashboards','falcon','parsers-repository','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Outfile = 'path'
        Query = @('filename','search_domain')
      }
      Headers = @{ Accept = 'application/octet-stream' }
    }
  }
  process {
    if (!$PSBoundParameters.Path) {
      # When 'Path' is not specified, use 'Filename'
      $PSBoundParameters['Path'] = Join-Path (Get-Location).Path (Split-Path $PSBoundParameters.Filename -Leaf)
    }
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path csv
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
function Receive-FalconNgsParser {
<#
.SYNOPSIS
Download a Falcon NGSIEM parser YAML template
.DESCRIPTION
Requires 'NGSIEM Parsers: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Parser identifier
.PARAMETER Repository
Repository name
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconNgsParser
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/parsers-template/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers-template/v1:get',Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('parsers-repository',IgnoreCase=$false)]
    [string]$Repository,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers-template/v1:get')]
    [switch]$Force

  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids','repository') }
    }
  }
  process {
    if (!$PSBoundParameters.Path) {
      # When 'Path' is not specified, use a combination of 'parser', 'repository', and 'id'
      $PSBoundParameters['Path'] = Join-Path (Get-Location).Path (('parser',$PSBoundParameters.Repository,
        $PSBoundParameters.Id -join '_'),'yaml' -join '.')
    }
    $Request = Write-NgsContent @Param -UserInput $PSBoundParameters -Property id
    if ($Request) {
      $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'yaml'
      $OutPath = Test-OutFile $PSBoundParameters.Path
      if ($OutPath.Category -eq 'ObjectNotFound') {
        Write-Error @OutPath
      } elseif ($PSBoundParameters.Path) {
        if ($OutPath.Category -eq 'WriteError' -and !$Force) {
          Write-Error @OutPath
        } elseif ($Request.yaml_template) {
          $OutParam = @{
            InputObject = $Request.yaml_template
            FilePath = $PSBoundParameters.Path
            Encoding = 'UTF8'
          }
          if ($PSBoundParameters.Force) { $OutParam['Force'] = $true }
          Out-File @OutParam
        }
      }
    }
  }
  end {
    if ($Request -and $OutParam -and (Test-Path $OutParam.FilePath)) {
      Get-ChildItem $OutParam.FilePath | Select-Object FullName,Length,LastWriteTime
    }
  }
}
function Receive-FalconNgsSavedQuery {
<#
.SYNOPSIS
Download a Falcon NGSIEM saved query YAML template
.DESCRIPTION
Requires 'NGSIEM Saved Queries: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Saved query identifier
.PARAMETER Domain
Repository or view
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconNgsSavedQuery
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:get',Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('all','dashboards','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:get')]
    [switch]$Force

  )
  process {
    if (!$PSBoundParameters.Path) {
      # When 'Path' is not specified, use a combination of 'query', 'search_domain', and 'id'
      $PSBoundParameters['Path'] = Join-Path (Get-Location).Path (('query',$PSBoundParameters.Domain,
        $PSBoundParameters.Id -join '_'),'yaml' -join '.')
    }
    $Request = Get-FalconNgsSavedQuery -Id $PSBoundParameters.Id -Domain $PSBoundParameters.Domain
    if ($Request) {
      $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'yaml'
      $OutPath = Test-OutFile $PSBoundParameters.Path
      if ($OutPath.Category -eq 'ObjectNotFound') {
        Write-Error @OutPath
      } elseif ($PSBoundParameters.Path) {
        if ($OutPath.Category -eq 'WriteError' -and !$Force) {
          Write-Error @OutPath
        } elseif ($Request.yaml_template) {
          $OutParam = @{
            InputObject = $Request.yaml_template
            FilePath = $PSBoundParameters.Path
            Encoding = 'UTF8'
          }
          if ($PSBoundParameters.Force) { $OutParam['Force'] = $true }
          Out-File @OutParam
        }
      }
    }
  }
  end {
    if ($Request -and $OutParam -and (Test-Path $OutParam.FilePath)) {
      Get-ChildItem $OutParam.FilePath | Select-Object FullName,Length,LastWriteTime
    }
  }
}
function Remove-FalconNgsDashboard {
<#
.SYNOPSIS
Remove Falcon NGSIEM dashboards
.DESCRIPTION
Requires 'NGSIEM Dashboards: Write'.
.PARAMETER Id
Dashboard identifier
.PARAMETER Domain
Repository or view
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsDashboard
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/dashboards/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','dashboards','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids','search_domain') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconNgsLookupFile {
<#
.SYNOPSIS
Remove Falcon NGSIEM lookup files
.DESCRIPTION
Requires 'NGSIEM Lookup Files: Write'.
.PARAMETER Filename
Lookup file name
.PARAMETER Domain
Repository or view
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/lookupfiles/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Filename,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','falcon','parsers-repository','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filename','search_domain') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconNgsParser {
<#
.SYNOPSIS
Remove Falcon NGSIEM parsers
.DESCRIPTION
Requires 'NGSIEM Parsers: Write'.
.PARAMETER Id
Parser identifier
.PARAMETER Repository
Repository
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsParser
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/parsers/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('parsers-repository',IgnoreCase=$false)]
    [string]$Repository
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids','repository') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconNgsSavedQuery {
<#
.SYNOPSIS
Remove Falcon NGSIEM saved queries
.DESCRIPTION
Requires 'NGSIEM Saved Queries: Write'.
.PARAMETER Id
Saved query identifier
.PARAMETER Domain
Repository or view
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsSavedQuery
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/savedqueries/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','dashboards','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids','search_domain') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconNgsDashboard {
<#
.SYNOPSIS
Create a Falcon NGSIEM dashboard from a YAML template
.DESCRIPTION
Requires 'NGSIEM Dashboards: Write'.
.PARAMETER Name
Dashboard name
.PARAMETER Domain
Repository or view
.PARAMETER Path
Path to YAML template
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconNgsDashboard
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/dashboards-template/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('yaml_template','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Formdata = @('name','search_domain','yaml_template') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconNgsLookupFile {
<#
.SYNOPSIS
Create a Falcon NGSIEM lookup file from a CSV
.DESCRIPTION
Requires 'NGSIEM Lookup Files: Write'.
.PARAMETER Filename
Lookup file name
.PARAMETER Domain
Repository or view
.PARAMETER Path
Path to CSV
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconNgsLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/lookupfiles/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:post',Mandatory,Position=1)]
    [string]$Filename,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','falcon','parsers-repository','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('file','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Formdata = @('file','filename','search_domain') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconNgsParser {
<#
.SYNOPSIS
Create a Falcon NGSIEM parser from a YAML template
.DESCRIPTION
Requires 'NGSIEM Parsers: Write'.
.PARAMETER Name
Parser name
.PARAMETER Repository
Repository name
.PARAMETER Path
Path to YAML template
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconNgsParser
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/parsers-template/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers-template/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers-template/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('parsers-repository',IgnoreCase=$false)]
    [string]$Repository,
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers-template/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('yaml_template','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Formdata = @('name','repository','yaml_template') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconNgsSavedQuery {
<#
.SYNOPSIS
Create a Falcon NGSIEM saved query from a YAML template
.DESCRIPTION
Requires 'NGSIEM Saved Queries: Write'.
.PARAMETER Domain
Repository or view
.PARAMETER Path
Path to YAML template
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconNgsSavedQuery
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidateSet('all','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('yaml_template','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Formdata = @('search_domain','yaml_template') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Update-FalconNgsDashboard {
<#
.SYNOPSIS
Update a Falcon NGSIEM dashboard using a YAML template
.DESCRIPTION
Requires 'NGSIEM Dashboards: Write'.
.PARAMETER Id
Dashboard identifier
.PARAMETER Domain
Repository or view
.PARAMETER Path
Path to YAML template
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconNgsDashboard
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/dashboards-template/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','falcon','parsers-repository','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('yaml_template','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Formdata = @('ids','search_domain','yaml_template') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Update-FalconNgsLookupFile {
<#
.SYNOPSIS
Update a Falcon NGSIEM lookup file using a CSV
.DESCRIPTION
Requires 'NGSIEM Lookup Files: Write'.
.PARAMETER Id
Lookup file identifier
.PARAMETER Domain
Repository or view
.PARAMETER Path
Path to CSV
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconNgsLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/lookupfiles/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Filename,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','falcon','parsers-repository','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('file','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Formdata = @('file','filename','search_domain') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Update-FalconNgsSavedQuery {
<#
.SYNOPSIS
Update a Falcon NGSIEM saved query using a YAML template
.DESCRIPTION
Requires 'NGSIEM Saved Queries: Write'.
.PARAMETER Id
Saved query identifier
.PARAMETER Domain
Repository or view
.PARAMETER Path
Path to YAML template
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconNgsSavedQuery
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('all','falcon','third-party',IgnoreCase=$false)]
    [Alias('search_domain')]
    [string]$Domain,
    [Parameter(ParameterSetName='/ngsiem-content/entities/savedqueries-template/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('yaml_template','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Formdata = @('ids','search_domain','yaml_template') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}