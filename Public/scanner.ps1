function Get-FalconQuickScan {
<#
.SYNOPSIS
Search for Falcon QuickScan results
.DESCRIPTION
Requires 'Quick Scan (Falcon Intelligence): Read'.
.PARAMETER Id
QuickScan identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconQuickScan
#>
    [CmdletBinding(DefaultParameterSetName='/scanner/queries/scans/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Intel.QuickScan',ParameterSetName='/scanner/entities/scans/v1:get')]
    [OutputType([string],ParameterSetName='/scanner/queries/scans/v1:get')]
    param(
        [Parameter(ParameterSetName='/scanner/entities/scans/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/scanner/queries/scans/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/scanner/queries/scans/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/scanner/queries/scans/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/scanner/queries/scans/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/scanner/queries/scans/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/scanner/queries/scans/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/scanner/queries/scans/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','filter','limit') }
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/scanner/entities/scans/v1:get' { 'Intel.QuickScan' }
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
function Get-FalconQuickScanQuota {
<#
.SYNOPSIS
Display monthly Falcon QuickScan quota
.DESCRIPTION
Requires 'Quick Scan (Falcon Intelligence): Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconQuickScanQuota
#>
    [CmdletBinding(DefaultParameterSetName='/scanner/queries/scans/v1:get',SupportsShouldProcess)]
    param()
    process {
        $Request = Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName -RawOutput -EA 0
        if ($Request.Result.Content) {
            (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta.quota
        } elseif ($Request) {
            throw "Unable to retrieve QuickScan quota. Check client permissions."
        }
    }
}
function New-FalconQuickScan {
<#
.SYNOPSIS
Submit a volume of files to Falcon QuickScan
.DESCRIPTION
'Id' values (Sha256 hashes) are retrieved from files that are uploaded using 'Send-FalconSample'. Files must be
uploaded before they can be used with Falcon QuickScan.

Time required for analysis increases with the number of samples in a volume but usually takes less than 1 minute.

Requires 'Quick Scan (Falcon Intelligence): Write'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconQuickScan
#>
    [CmdletBinding(DefaultParameterSetName='/scanner/entities/scans/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/scanner/entities/scans/v1:post',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline,Position=1)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [Alias('samples','Ids','sha256')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('samples') }}
            Max = 1000
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