function Edit-FalconHorizonPolicy {
<#
.Synopsis
Updates a policy setting - can be used to override policy severity or to disable a policy entirely.
.Parameter PolicyId
Falcon Horizon policy identifier
.Parameter Enabled
Policy enablement status
.Parameter Severity
Severity level
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/settings/entities/policy/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/settings/entities/policy/v1:patch', Mandatory = $true, Position = 1)]
        [int32] $PolicyId,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:patch', Mandatory = $true, Position = 2)]
        [boolean] $Enabled,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:patch', Mandatory = $true, Position = 3)]
        [ValidateSet('informational', 'medium', 'high')]
        [string] $Severity
    )
    begin {
        $Fields = @{
            PolicyId = 'policy_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('severity', 'policy_id', 'enabled')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconHorizonSchedule {
<#
.Synopsis
Updates Falcon Horizon scan schedule configuration for one or more cloud platforms.
.Parameter CloudPlatform
Cloud platform
.Parameter ScanSchedule
Scan interval
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/settings/scan-schedule/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/settings/scan-schedule/v1:post', Mandatory = $true, Position = 2)]
        [ValidateSet('2h', '6h', '12h', '24h')]
        [string] $ScanSchedule
    )
    begin {
        $Fields = @{
            CloudPlatform = 'cloud_platform'
            ScanSchedule  = 'scan_schedule'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('cloud_platform', 'scan_schedule')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonPolicy {
<#
.Synopsis
Returns information about current Falcon Horizon policy settings.
.Parameter Ids
One or more Falcon Horizon policy identifiers
.Parameter PolicyId
Falcon Horizon policy identifier
.Parameter Service
Cloud service type
.Parameter CloudPlatform
Cloud platform
.Parameter Detailed
Retrieve detailed information
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/settings/entities/policy/v1:get')]
    param(
        [Parameter(ParameterSetName = '/settings/entities/policy-details/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{*}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 1)]
        [ValidatePattern('^\d{*}$')]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 2)]
        [ValidateSet('EC2', 'IAM', 'KMS', 'ACM', 'ELB', 'NLB/ALB', 'EBS', 'RDS', 'S3', 'Redshift',
            'NetworkSecurityGroup', 'VirtualNetwork', 'Disk', 'PostgreSQL', 'AppService', 'KeyVault',
            'VirtualMachine', 'Monitor', 'StorageAccount', 'LoadBalancer', 'SQLServer')]
        [string] $Service,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 3)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get')]
        [switch] $Detailed
    )
    begin {
        $Fields = @{
            CloudPlatform = 'cloud-platform'
            PolicyId      = 'policy-id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('ids', 'service', 'policy-id', 'cloud-platform')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonSchedule {
<#
.Synopsis
Returns Falcon Horizon scan schedule configuration for one or more cloud platforms.
.Parameter CloudPlatform
Cloud platform
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/settings/scan-schedule/v1:get')]
    param(
        [Parameter(ParameterSetName = '/settings/scan-schedule/v1:get', Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [array] $CloudPlatform
    )
    begin {
        $Fields = @{
            CloudPlatform = 'cloud-platform'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('cloud-platform')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}