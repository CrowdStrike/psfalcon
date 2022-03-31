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
https://github.com/crowdstrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',Position=1)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,

        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','scan-type') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process { if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}}
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconDiscoverGcpAccount {
<#
.SYNOPSIS
Search for Falcon Discover for Cloud GCP accounts
.DESCRIPTION
Requires 'D4C Registration: Read'.
.PARAMETER ScanType
Scan type
.PARAMETER Id
GCP account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-gcp/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-gcp/entities/account/v1:get',Position=1)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,

        [Parameter(ParameterSetName='/cloud-connect-gcp/entities/account/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{10,}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','scan-type') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process { if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}}
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
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
https://github.com/crowdstrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('subscription_id')]
        [string]$SubscriptionId,

        [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
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
function New-FalconDiscoverGcpAccount {
<#
.SYNOPSIS
Provision Falcon Discover for Cloud GCP accounts
.DESCRIPTION
Requires 'D4C Registration: Write'.
.PARAMETER ParentId
GCP project identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-gcp/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-gcp/entities/account/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('parent_id')]
        [string]$ParentId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('parent_id') }}
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
https://github.com/crowdstrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get')]
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
function Receive-FalconDiscoverGcpScript {
<#
.SYNOPSIS
Download a Bash script to grant Falcon Discover for Cloud access using GCP CLI
.DESCRIPTION
Requires 'D4C Registration: Read'.
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-gcp/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-gcp/entities/user-scripts-download/v1:get',Mandatory,
           Position=1)]
        [string]$Path,

        [Parameter(ParameterSetName='/cloud-connect-gcp/entities/user-scripts-download/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{ Outfile = 'path' }
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
https://github.com/crowdstrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('id') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}