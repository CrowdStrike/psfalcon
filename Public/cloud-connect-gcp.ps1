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
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-gcp/entities/account/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/cloud-connect-gcp/entities/account/v1:get',Position=1)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,
        [Parameter(ParameterSetName='/cloud-connect-gcp/entities/account/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{10,}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','scan-type') }
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
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-gcp/entities/account/v1:post',
        SupportsShouldProcess)]
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
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-gcp/entities/user-scripts-download/v1:get',
        SupportsShouldProcess)]
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