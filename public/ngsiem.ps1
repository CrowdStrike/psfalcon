function Edit-FalconNgsDataConnection {
<#
.SYNOPSIS
Modify a Falcon NGSIEM data connection
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER Id
Data connection identifier
.PARAMETER Name
Data connection name
.PARAMETER Parser
Parser name
.PARAMETER Description
Data connection description
.PARAMETER ConfigId
Configuration identifier
.PARAMETER Config
An object containing external data source connection settings ('auth', 'name', 'params')
.PARAMETER HostEnrichment
Enable host enrichment
.PARAMETER UserEnrichment
Enable user enrichment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsDataConnection
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connections/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [ValidateLength(1,50)]
    [string]$Name,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Parser,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidateLength(1,500)]
    [string]$Description,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [Alias('config_id')]
    [string]$ConfigId,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [object]$Config,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('enable_host_enrichment')]
    [boolean]$HostEnrichment,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:patch',ValueFromPipelineByPropertyName,
      Position=8)]
    [Alias('enable_user_enrichment')]
    [boolean]$UserEnrichment
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('config_id','config','description','enable_host_enrichment','enable_user_enrichment','name',
            'parser')
        }
        Query = @('ids')
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconNgsDataConnectionStatus {
<#
.SYNOPSIS
Update the status of a Falcon NGSIEM data connection
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER Status
Status value
.PARAMETER Id
Data connection identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsDataConnectionStatus
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connections/status/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connections/status/v1:patch',Mandatory,Position=1)]
    [ValidateSet('Pause','Resume',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/status/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [Alias('ids')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('status') }; Query = @('ids') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconNgsDataConnectorConfig {
<#
.SYNOPSIS
Edit a Falcon NGSIEM data connector configuration
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER Id
Data connector configuration identifier
.PARAMETER ConnectorId
Data connector identifier
.PARAMETER Config
Object containing configuration properties ('auth', 'name', 'params')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsDataConnectorConfig
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connectors/configs/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('connector_id')]
    [string]$ConnectorId,
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [object]$Config
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          config = @('auth','name','params')
          root = @('connector_id')
        }
        Query = @('ids')
      }
    }
  }
  process {
    $PSBoundParameters.Config = [PSCustomObject]$PSBoundParameters.Config | Select-Object $Param.Format.Body.config
    $Param.Format.Body.root += 'config'
    [void]$Param.Format.Body.Remove('config')
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconNgsDataConnection {
<#
.SYNOPSIS
Search for configured Falcon NGSIEM data connections or retrieve their status
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Read'.
.PARAMETER Id
Data connection identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Status
Limit results to provisioning status for provided data connection identifier
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsDataConnection
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/combined/connections/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Parameter(ParameterSetName='/ngsiem/entities/connections/status/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/ngsiem/combined/connections/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ngsiem/combined/connections/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/ngsiem/combined/connections/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/ngsiem/combined/connections/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/status/v1:get',Mandatory)]
    [switch]$Status,
    [Parameter(ParameterSetName='/ngsiem/combined/connections/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ngsiem/combined/connections/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconNgsDataConnectionToken {
<#
.SYNOPSIS
Return the ingest token for a Falcon NGSIEM data connection
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Read'.
.PARAMETER Id
Data connection identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsDataConnectionToken
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connections/token/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connections/token/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconNgsDataConnector {
<#
.SYNOPSIS
Search for available Falcon NGSIEM data connectors
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsDataConnector
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/combined/connectors/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/combined/connectors/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ngsiem/combined/connectors/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/ngsiem/combined/connectors/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/ngsiem/combined/connectors/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/ngsiem/combined/connectors/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ngsiem/combined/connectors/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','limit','offset','sort') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconNgsDataConnectorConfig {
<#
.SYNOPSIS
List configurations for a Falcon NGSIEM data connector
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Read'.
.PARAMETER Id
Data connector identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsDataConnectorConfig
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connectors/configs/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconNgsDataConnection {
<#
.SYNOPSIS
Create a Falcon NGSIEM data connection
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER ConnectorId
Data connector identifier
.PARAMETER Name
Data connection name
.PARAMETER Parser
Parser name
.PARAMETER Description
Data connection description
.PARAMETER ConnectorType
Data connector type
.PARAMETER VendorName
Vendor name
.PARAMETER VendorProductName
Vendor product name
.PARAMETER HostEnrichment
Enable host enrichment [default: false]
.PARAMETER UserEnrichment
Enable user enrichment [default: false]
.PARAMETER ConfigId
Configuration identifier
.PARAMETER Config
An object containing external data source connection settings ('auth', 'name', 'params')
.PARAMETER LogSource
Log sources to collect (when using ConnectorType 'PULL')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconNgsDataConnection
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connections/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('connector_id','id')]
    [string]$ConnectorId,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=2)]
    [ValidateLength(1,50)]
    [string]$Name,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Parser,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,Position=4)]
    [ValidateLength(1,500)]
    [string]$Description,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,Position=5)]
    [ValidateSet('PULL','PUSH',IgnoreCase=$false)]
    [Alias('connector_type','type')]
    [string]$ConnectorType,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,Position=6)]
    [Alias('vendor_name')]
    [string]$VendorName,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,Position=7)]
    [Alias('vendor_product_name')]
    [string]$VendorProductName,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,Position=8)]
    [Alias('enable_host_enrichment')]
    [boolean]$HostEnrichment,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,Position=9)]
    [Alias('enable_user_enrichment')]
    [boolean]$UserEnrichment,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('config_id')]
    [string]$ConfigId,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,
      Position=11)]
    [object]$Config,
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:post',ValueFromPipelineByPropertyName,
      Position=12)]
    [Alias('log_sources')]
    [string[]]$LogSource
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('config_id','config','connector_id','connector_type','description','enable_host_enrichment',
            'enable_user_enrichment','log_sources','name','parser','vendor_name','vendor_product_name')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconNgsDataConnectorConfig {
<#
.SYNOPSIS
Create a Falcon NGSIEM data connector configuration
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER ConnectorId
Data connector identifier
.PARAMETER Config
Object containing configuration properties ('auth', 'name', 'params')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconNgsDataConnectorConfig
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connectors/configs/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('connector_id')]
    [string]$ConnectorId,
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [object]$Config
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          config = @('auth','name','params')
          root = @('connector_id')
        }
      }
    }
  }
  process {
    $PSBoundParameters.Config = [PSCustomObject]$PSBoundParameters.Config | Select-Object $Param.Format.Body.config
    $Param.Format.Body.root += 'config'
    [void]$Param.Format.Body.Remove('config')
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconNgsDataConnection {
<#
.SYNOPSIS
Delete a Falcon NGSIEM data connection
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER Id
Data connection identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsDataConnection
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connections/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connections/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconNgsDataConnectorConfig {
<#
.SYNOPSIS
Delete a Falcon NGSIEM data connector configuration
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER Id
Data connector configuration identifier
.PARAMETER ConnectorId
Data connector identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsDataConnectorConfig
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connectors/configs/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/ngsiem/entities/connectors/configs/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('connector_id')]
    [string]$ConnectorId
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('connector_id','ids') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Reset-FalconNgsDataConnectionToken {
<#
.SYNOPSIS
Regenerate the ingest token for a Falcon NGSIEM data connection
.DESCRIPTION
Requires 'NGSIEM Data Connections API: Write'.
.PARAMETER Id
Data connection identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Reset-FalconNgsDataConnectionToken
#>
  [CmdletBinding(DefaultParameterSetName='/ngsiem/entities/connections/token/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ngsiem/entities/connections/token/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}