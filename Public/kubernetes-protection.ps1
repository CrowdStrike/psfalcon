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
    [OutputType('CrowdStrike.Falcon.Meta.Response',
        ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:patch')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:patch',Position=1)]
        [string]$Region,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','region') }
            Schema = 'Meta.Response'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
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
    [OutputType('CrowdStrike.Falcon.Cwp.Azure.TenantConfig',
        ParameterSetName='/kubernetes-protection/entities/service-principal/azure/v1:patch')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/service-principal/azure/v1:patch',Mandatory,
            Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('client_id')]
        [string]$ClientId,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/service-principal/azure/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('id','client_id') }
            Schema = 'Cwp.Azure.TenantConfig'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconContainerAwsAccount {
<#
.SYNOPSIS
Search for Falcon Container Security AWS accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
AWS account identifier
.PARAMETER Status
Filter by account status
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
    [OutputType('CrowdStrike.Falcon.Cwp.Aws.Account',
        ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',Position=2)]
        [ValidateSet('provisioned','operational',IgnoreCase=$false)]
        [string]$Status,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get',Position=3)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','offset','limit','status') }
            Schema = 'Cwp.Aws.Account'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconContainerAzureAccount {
<#
.SYNOPSIS
Search for Falcon Container Security Azure accounts
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
Azure tenant identifier
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER Status
Filter by account status
.PARAMETER IsHorizonAcct
Filter by whether an account originates from Horizon or not
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
    [OutputType('CrowdStrike.Falcon.Cwp.Azure.Account',
        ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('subscription_id')]
        [string[]]$SubscriptionId,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',Position=3)]
        [ValidateSet('operational','provisioned',IgnoreCase=$false)]
        [string]$Status,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:get',Position=4)]
        [Alias('is_horizon_acct')]
        [boolean]$IsHorizonAcct,
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
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','status','limit','is_horizon_acct','offset','subscription_id') }
            Schema = 'Cwp.Azure.Account'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconContainerAzureConfig {
<#
.SYNOPSIS
Retrieve Falcon Container Security Azure tenant configurations
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
    [OutputType('CrowdStrike.Falcon.Cwp.Azure.TenantConfig',
        ParameterSetName='/kubernetes-protection/entities/config/azure/v1:get')]
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
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('offset','ids','limit') }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/kubernetes-protection/entities/config/azure/v1:get' {
                    'CrowdStrike.Falcon.Cwp.Azure.TenantConfig'
                }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
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
    [OutputType('CrowdStrike.Falcon.Cwp.Cloud',
        ParameterSetName='/kubernetes-protection/entities/cloud-locations/v1:get')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/cloud-locations/v1:get',
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('clouds')]
        [string[]]$Cloud
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('clouds') }
            Schema = 'Cwp.Cloud'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Cloud) { @($Cloud).foreach{ $List.Add($_) }}
    }
    end {
        if ($List) {
            $PSBoundParameters['Cloud'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconContainerCluster {
<#
.SYNOPSIS
Search for Falcon Container Security clusters
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Id
Cluster account identifier
.PARAMETER Location
Cloud provider location
.PARAMETER ClusterName
Cluster name
.PARAMETER ClusterService
Cluster service
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContainerCluster
#>
    [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get',
        SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Cwp.Cluster',
        ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get',
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [Alias('account_ids','Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get',Position=2)]
        [Alias('Locations')]
        [string[]]$Location,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get',Position=3)]
        [Alias('cluster_names','ClusterNames')]
        [string[]]$ClusterName,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get',Position=4)]
        [ValidateSet('eks',IgnoreCase=$false)]
        [Alias('cluster_service')]
        [string]$ClusterService,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get',Position=5)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('limit','cluster_names','account_ids','offset','cluster_service','locations')
            }
            Schema = 'Cwp.Cluster'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
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
    [OutputType('CrowdStrike.Falcon.Meta.Response',
        ParameterSetName='/kubernetes-protection/entities/scan/trigger/v1:post')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/scan/trigger/v1:post',Mandatory,
           Position=1)]
        [ValidateSet('dry-run','full','cluster-refresh',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('scan_type') }
            Schema = 'Meta.Response'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
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
    [OutputType('CrowdStrike.Falcon.Cwp.Aws.AccountRequest',
        ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:post')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:post',Mandatory,
           Position=1)]
        [string]$Region,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('account_id')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('account_id','region') }}
            Schema = 'Cwp.Aws.AccountRequest'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
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
    [OutputType('CrowdStrike.Falcon.Meta.Response',
        ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:post')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:post',Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('subscription_id')]
        [string]$SubscriptionId,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:post',Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('tenant_id')]
        [string]$TenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('subscription_id','tenant_id') }}
            Schema = 'Meta.Response'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
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
    process { Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName }
}
function Receive-FalconContainerYaml {
<#
.SYNOPSIS
Download a sample Helm values.yaml file
.DESCRIPTION
Requires 'Kubernetes Protection: Read'.
.PARAMETER Path
Destination path
.PARAMETER ClusterName
Cluster name
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconContainerYaml
#>
    [CmdletBinding(DefaultParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get',Mandatory,
           Position=1)]
        [string]$Path,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [Alias('cluster_name')]
        [string]$ClusterName,
        [Parameter(ParameterSetName='/kubernetes-protection/entities/integration/agent/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/yaml' }
            Format = @{
                Query = @('cluster_name')
                Outfile = 'path'
            }
        }
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
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }}
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
    [OutputType('CrowdStrike.Falcon.Meta.Response',
        ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:delete')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/aws/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
            Schema = 'Meta.Response'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
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
    [OutputType('CrowdStrike.Falcon.Meta.Response',
        ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:delete')]
    param(
        [Parameter(ParameterSetName='/kubernetes-protection/entities/accounts/azure/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
            Schema = 'Meta.Response'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}