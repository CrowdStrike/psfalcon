function Get-FalconZta {
<#
.SYNOPSIS
Search for Zero Trust Assessment results
.DESCRIPTION
Requires 'Zero Trust Assessment: Read'.
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconZta
#>
    [CmdletBinding(DefaultParameterSetName='/zero-trust-assessment/entities/audit/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/zero-trust-assessment/entities/assessments/v1:get',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids','device_id','host_ids','aid')]
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