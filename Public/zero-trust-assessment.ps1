function Get-FalconZta {
<#
.SYNOPSIS
Search for Zero Trust Assessment results
.DESCRIPTION
Requires 'Zero Trust Assessment: Read'.
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Zero-Trust-Assessment
#>
    [CmdletBinding(DefaultParameterSetName='/zero-trust-assessment/entities/audit/v1:get')]
    param(
        [Parameter(ParameterSetName='/zero-trust-assessment/entities/assessments/v1:get',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('ids','device_id','host_ids','aid')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
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