function Edit-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Modify the default Falcon Horizon Azure client or subscription identifier
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER Id
Azure client identifier
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier, required when multiple tenants have been registered
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconHorizonAzureAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [string]$Id,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
            Mandatory,ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('subscription_id')]
        [string]$SubscriptionId,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',
            ValueFromPipelineByPropertyName,Position=2)]
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('tenant-id','tenant_id')]
        [string]$TenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('tenant-id','id','subscription_id') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Search for Falcon Horizon Azure accounts
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER Id
Azure account identifier
.PARAMETER ScanType
Scan type
.PARAMETER Status
Azure account status
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonAzureAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=1)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=2)]
        [ValidateSet('provisioned','operational',IgnoreCase=$false)]
        [string]$Status,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('scan-type','offset','ids','status','limit') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconHorizonAzureCertificate {
<#
.SYNOPSIS
Retrieve the base64 encoded certificate for a Falcon Horizon Azure tenant
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER Refresh
Refresh certificate [default: false]
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonAzureCertificate
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/download-certificate/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/download-certificate/v1:get',Position=1)]
        [boolean]$Refresh,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/download-certificate/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [Alias('tenant_id')]
        [string[]]$TenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('refresh','tenant_id') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function New-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Provision a Falcon Horizon Azure account
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconHorizonAzureAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('subscription_id')]
        [string]$SubscriptionId,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('tenant_id')]
        [string]$TenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('subscription_id','tenant_id') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Receive-FalconHorizonAzureScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Horizon access using Azure Cloud Shell
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER Path
Destination path
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconHorizonAzureScript
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',Mandatory,
            Position=1)]
        [string]$Path,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('tenant-id','tenant_id')]
        [string]$TenantId,
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{
                Query = @('tenant-id')
                Outfile = 'path'
            }
        }
    }
    process {
        $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'sh'
        $OutPath = Test-OutFile $PSBoundParameters.Path
        if ($OutPath.Category -eq 'ObjectNotFound') {
            Write-Error @OutPath
        } elseif ($PSBoundParameters.Path) {
            if ($OutPath.Category -eq 'WriteError' -and !$Force) {
                Write-Error @OutPath
            } else {
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Remove-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Remove Falcon Horizon Azure accounts
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER Id
Azure account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconHorizonAzureAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
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