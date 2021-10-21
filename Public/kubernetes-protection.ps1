function Edit-FalconContainerAwsAccount {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:patch', Position = 2)]
        [string] $Region
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'region')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconContainerAwsAccount {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get', Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get', Position = 2)]
        [ValidateSet('provisioned', 'operational')]
        [string] $Status,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get', Position = 3)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit', 'status')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconContainerCloud {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/cloud-locations/v1:get')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/cloud-locations/v1:get', Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [array] $Clouds
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('clouds')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconContainerCluster {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get', Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get', Position = 2)]
        [array] $Locations,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get', Position = 3)]
        [array] $ClusterNames,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get', Position = 4)]
        [ValidateSet('eks')]
        [string] $ClusterService,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get', Position = 5)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get', Position = 6)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/kubernetes/clusters/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            ClusterNames   = 'cluster_names'
            ClusterService = 'cluster_service'
            Ids            = 'account_ids'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'cluster_names', 'account_ids', 'offset', 'cluster_service', 'locations')
            }
        }
        Invoke-Falcon @Param
    }
}
function Invoke-FalconContainerScan {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/scan/trigger/v1:post')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/scan/trigger/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('dry-run', 'full', 'cluster-refresh')]
        [string] $ScanType
    )
    begin {
        $Fields = @{
            ScanType = 'scan_type'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('scan_type')
            }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconContainerAwsAccount {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:post')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:post', Mandatory = $true,
            Position = 2)]
        [string] $Region
    )
    begin {
        $Fields = @{
            Id = 'account_id'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('account_id', 'region')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconContainerKey {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/integration/api-key/v1:post')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}
function Receive-FalconContainerYaml {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/integration/agent/v1:get')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/integration/agent/v1:get',
            Mandatory = $true, Position = 1)]
        [string] $ClusterName,

        [Parameter(ParameterSetName = '/kubernetes-protection/entities/integration/agent/v1:get',
            Mandatory = $true, Position = 2)]
        [ValidatePattern('^*\.yaml$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    begin {
        $Fields = @{
            ClusterName = 'cluster_name'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                Accept = 'application/yaml'
            }
            Format   = @{
                Query   = @('cluster_name')
                Outfile = 'path'
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconContainerAwsAccount {
    [CmdletBinding(DefaultParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/kubernetes-protection/entities/accounts/aws/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [array] $Ids
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
        Invoke-Falcon @Param
    }
}