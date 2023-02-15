function Get-FalconDiscoverAzureAccount {
<#
.SYNOPSIS
Search for Falcon Discover for Cloud Azure accounts
.DESCRIPTION
Requires 'D4C Registration: Read'.
.PARAMETER ScanType
Scan type
.PARAMETER Id
Azure account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAzureAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/account/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Azure.Account',
        ParameterSetName='/cloud-connect-azure/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',Position=1)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',ValueFromPipelineByPropertyName,
            ValueFromPipeline,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','scan-type') }
            Schema = 'Horizon.Azure.Account'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconDiscoverAzureCertificate {
<#
.SYNOPSIS
Retrieve the base64 encoded certificate for a Falcon Discover Azure tenant
.DESCRIPTION
Requires 'D4C Registration: Read'.
.PARAMETER Refresh
Refresh certificate [default: false]
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAzureCertificate
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get',
        SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Azure.Certificate',
        ParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get',Position=1)]
        [boolean]$Refresh,
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('tenant_id')]
        [string[]]$TenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('refresh','tenant_id') }
            Schema = 'Horizon.Azure.Certificate'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function New-FalconDiscoverAzureAccount {
<#
.SYNOPSIS
Provision Falcon Discover for Cloud Azure accounts
.DESCRIPTION
Requires 'D4C Registration: Write'.
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDiscoverAzureAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/account/v1:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Azure.Account',
        ParameterSetName='/cloud-connect-azure/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('subscription_id')]
        [string]$SubscriptionId,
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
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
            Schema = 'Horizon.Azure.Account'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Receive-FalconDiscoverAzureScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Discover for Cloud access using Azure Cloud Shell
.DESCRIPTION
Requires 'D4C Registration: Read'.
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconDiscoverAzureScript
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get',
        SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Azure.Script',
        ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get',Mandatory,
           Position=1)]
        [string]$Path,
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{ Outfile = 'path' }
            Schema = 'Horizon.Azure.Script'
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
function Update-FalconDiscoverAzureAccount {
<#
.SYNOPSIS
Update the Azure Service Principal for Falcon Discover for Cloud
.DESCRIPTION
Requires 'D4C Registration: Write'.
.PARAMETER Id
Azure client identifier for the associated Service Principal
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconDiscoverAzureAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch',
        SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Azure.Account.Principal',
        ParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('id') }
            Schema = 'Horizon.Azure.Account.Principal'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}