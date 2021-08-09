function Get-FalconZta {
<#
.Synopsis
Search for Zero Trust Assessment results
.Parameter Ids
Host identifier(s)
.Role
zero-trust-assessment:read
#>
    [CmdletBinding(DefaultParameterSetName = '/zero-trust-assessment/entities/assessments/v1:get')]
    param(
        [Parameter(ParameterSetName = '/zero-trust-assessment/entities/assessments/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}