function Edit-FalconContainerAwsAccount {
<#
.SYNOPSIS
Modify Falcon Container Security AWS accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.PARAMETER Region
AWS cloud region
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconContainerAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:patch',Position=1)]
    [string]$Region,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^\d{12}$')]
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
function Edit-FalconContainerAzureAccount {
<#
.SYNOPSIS
Modify the client identifier for a Falcon Container Security Azure account
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.PARAMETER ClientId
Azure client identifier
.PARAMETER Id
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconContainerAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/service-principal/azure/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/service-principal/azure/v1:patch',Mandatory,
      Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('client_id')]
    [string]$ClientId,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/service-principal/azure/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconContainerAccount {
<#
.SYNOPSIS
Return provisioned Falcon Container Security accounts and known clusters
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
Cluster account identifier
.PARAMETER Location
Cloud provider location
.PARAMETER ClusterService
Cluster service
.PARAMETER ClusterStatus
Cluster status
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get',Position=2)]
    [Alias('locations')]
    [string[]]$Location,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get',Position=3)]
    [ValidateSet('aks','eks',IgnoreCase=$false)]
    [Alias('cluster_service')]
    [string[]]$ClusterService,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get',Position=4)]
    [ValidateSet('Not Installed','Running','Stopped',IgnoreCase=$false)]
    [Alias('cluster_status')]
    [string[]]$ClusterStatus,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get',Position=5)]
    [int]$Limit,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud_cluster/v1:get')]
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerAwsAccount {
<#
.SYNOPSIS
Return Falcon Container Security AWS accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
AWS account identifier
.PARAMETER Status
Filter by account status
.PARAMETER IsFcsAcct
Restrict results to Falcon Cloud Security
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^\d{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',Position=2)]
    [ValidateSet('provisioned','operational',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',Position=3)]
    [ValidateSet('false','true',IgnoreCase=$false)]
    [Alias('is_horizon_acct','IsHorizonAcct')]
    [string]$IsFcsAcct,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',Position=4)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get')]
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerAzureAccount {
<#
.SYNOPSIS
Return Falcon Container Security Azure accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
Azure tenant identifier
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER Status
Filter by account status
.PARAMETER IsFcsAcct
Restrict results to Falcon Cloud Security
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('subscription_id')]
    [string[]]$SubscriptionId,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',Position=3)]
    [ValidateSet('operational','provisioned',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',Position=4)]
    [Alias('is_horizon_acct','IsHorizonAcct')]
    [boolean]$IsFcsAcct,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',Position=5)]
    [int]$Limit,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get')]
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerAzureConfig {
<#
.SYNOPSIS
Return Falcon Container Security Azure tenant configurations
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
Azure tenant identifier
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAzureConfig
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/config/azure/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/config/azure/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/config/azure/v1:get',Position=2)]
    [int]$Limit,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/config/azure/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/config/azure/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/config/azure/v1:get')]
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerAzureScript {
<#
.SYNOPSIS
Return Falcon Container Security script
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
Azure tenant identifier
.PARAMETER SubscriptionId
Azure subscription identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAzureScript
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/user-script/azure/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/user-script/azure/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/user-script/azure/v1:get',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('subscription_id')]
    [string[]]$SubscriptionId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconContainerAzureTenant {
<#
.SYNOPSIS
Return Falcon Container Security Azure tenants
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
Azure tenant identifier
.PARAMETER Status
Cluster Status
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerAzureTenant
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/tenants/azure/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/tenants/azure/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/tenants/azure/v1:get',Position=2)]
    [ValidateSet('Not Installed','Running','Stopped',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/tenants/azure/v1:get',Position=3)]
    [int]$Limit,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/tenants/azure/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/tenants/azure/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/tenants/azure/v1:get')]
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerCloud {
<#
.SYNOPSIS
Return Falcon Container Security cloud provider locations
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Cloud
Cloud provider
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerCloud
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/cloud-locations/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud-locations/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
    [Alias('clouds')]
    [string[]]$Cloud
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Cloud) { @($Cloud).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Cloud'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconContainerScript {
<#
.SYNOPSIS
Return bash scripts for Falcon Cloud Security registration
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerScript
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/gen/scripts/v1:get',
    SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
}
function Invoke-FalconContainerScan {
<#
.SYNOPSIS
Initiate a Falcon Container Security scan
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.PARAMETER ScanType
Scan type
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconContainerScan
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/scan/trigger/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/scan/trigger/v1:post',Mandatory,Position=1)]
    [ValidateSet('cluster-refresh','dry-run','full',IgnoreCase=$false)]
    [Alias('scan_type')]
    [string]$ScanType
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconContainerAwsAccount {
<#
.SYNOPSIS
Provision Falcon Container Security AWS accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.PARAMETER Region
AWS cloud region
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconContainerAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:post',Mandatory,Position=1)]
    [string]$Region,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^\d{12}$')]
    [Alias('account_id')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconContainerAzureAccount {
<#
.SYNOPSIS
Provision Falcon Container Security Azure accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconContainerAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:post',Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('subscription_id')]
    [string]$SubscriptionId,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_id')]
    [string]$TenantId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconContainerKey {
<#
.SYNOPSIS
Regenerate the API key for Falcon Container Security Docker registry integrations
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconContainerKey
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/integration/api-key/v1:post',
    SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
}
function Receive-FalconContainerYaml {
<#
.SYNOPSIS
Download a sample Helm values.yaml file
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER ClusterName
Cluster name
.PARAMETER IsSelfManagedCluster
Restrict results to clusters that are not managed by the cloud provider
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconContainerYaml
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('cluster_name')]
    [string]$ClusterName,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get',Position=2)]
    [Alias('is_self_managed_cluster')]
    [boolean]$IsSelfManagedCluster,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get',Mandatory,Position=3)]
    [string]$Path,
    [Parameter(ParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/yaml' }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'yaml'
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
function Remove-FalconContainerAwsAccount {
<#
.SYNOPSIS
Remove Falcon Container Security AWS accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconContainerAwsAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^\d{12}$')]
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
function Remove-FalconContainerAzureAccount {
<#
.SYNOPSIS
Remove Falcon Container Security Azure accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Write'.
.PARAMETER Id
Azure subscription identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconContainerAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
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