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
    [Parameter(ParameterSetName='/ngsiem-content/queries/dashboards/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Parameter(ParameterSetName='/ngsiem-content/entities/dashboards-template/v1:get',Mandatory,Position=1)]
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Write-NgsContent @Param -UserInput $PSBoundParameters -Property id }
}
function Get-FalconNgsLookupFile {
<#
.SYNOPSIS
Search for Falcon NGSIEM lookup files
.DESCRIPTION
Requires 'NGSIEM Lookup Files: Read'.
.PARAMETER Filename
Lookup file name
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
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:get',Mandatory,
      ValueFromPipelineByPropertyName)]
    [string]$Filename,
    [Parameter(ParameterSetName='/ngsiem-content/queries/lookupfiles/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Parameter(ParameterSetName='/ngsiem-content/entities/lookupfiles/v1:get',Mandatory,Position=1)]
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Write-NgsContent @Param -UserInput $PSBoundParameters -Property filename }
}
function Get-FalconNgsParser {
<#
.SYNOPSIS
Retrieve Parser in NGSIEM as LogScale YAML Template
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
      ValueFromPipelineByPropertyName)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem-content/queries/parsers/v1:get',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/ngsiem-content/entities/parsers/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Write-NgsContent @Param -UserInput $PSBoundParameters -Property id }
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}