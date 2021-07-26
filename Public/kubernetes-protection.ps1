function New-FalconAccounts {
<#
.Synopsis
Creates a new AWS account in our system for a customer and generates the installation script
.Parameter AccountId

.Parameter Region

.Role
kubernetes-protection:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:post', Mandatory = $true)]
        [string] $AccountId,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:post', Mandatory = $true)]
        [string] $Region
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('account_id', 'region')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconAccounts {
<#
.Synopsis
Delete AWS accounts.
.Parameter Ids
One or more XXX identifiers
.Role
kubernetes-protection:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:delete', Mandatory = $true)]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconAccounts {
<#
.Synopsis
Provides a list of AWS accounts.
.Parameter Ids
One or more XXX identifiers
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Parameter Status

.Role
kubernetes-protection:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get')]
        [int] $Offset,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get')]
        [int] $Limit,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get')]
        [ValidateSet('provisioned', 'operational')]
        [string] $Status
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('ids', 'offset', 'limit', 'status')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIntegration {
<#
.Synopsis
Provides a sample Helm values.yaml file for a customer to install alongside the agent Helm chart
.Parameter ClusterName

.Role
kubernetes-protection:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/integration/agent/v1:get', Mandatory = $true)]
        [string] $ClusterName
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/yaml'
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('cluster_name')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconKubernetes {
<#
.Synopsis
Provides the clusters acknowledged by the Kubernetes Protection service
.Parameter Limit
Maximum number of results per request
.Parameter ClusterNames

.Parameter AccountIds

.Parameter Offset
Position to begin retrieving results
.Parameter ClusterService

.Parameter Locations

.Role
kubernetes-protection:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [int] $Limit,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [array] $ClusterNames,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [array] $AccountIds,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [int] $Offset,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [ValidateSet('eks')]
        [string] $ClusterService,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [array] $Locations
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('limit', 'cluster_names', 'account_ids', 'offset', 'cluster_service', 'locations')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconAccounts {
<#
.Synopsis
Updates the AWS account per the query parameters provided
.Parameter Ids
One or more XXX identifiers
.Parameter Region

.Role
kubernetes-protection:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:patch', Mandatory = $true)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:patch')]
        [ValidatePattern('^[a-z\d-]+$')]
        [string] $Region
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('ids', 'region')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconScan {
<#
.Synopsis
Triggers a dry run or a full scan of a customers kubernetes footprint
.Parameter ScanType

.Role
kubernetes-protection:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/scan/trigger/v1:post', Mandatory = $true)]
        [ValidateSet('dry-run', 'full', 'cluster-refresh')]
        [string] $ScanType
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('scan_type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconIntegration {
<#
.Synopsis
Regenerate API key for docker registry integrations

.Role
kubernetes-protection:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
    
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('scan_type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCloudLocations {
<#
.Synopsis
Provides the cloud locations acknowledged by the Kubernetes Protection service
.Parameter Clouds

.Role
kubernetes-protection:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/cloud-locations/v1:get')]
        [ValidateSet('aws', 'azure', 'gcp')]
        [array] $Clouds
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('clouds')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
