function Get-FalconZTA {
<#
.Synopsis
Get Zero Trust Assessment data for one or more hosts
.Parameter Ids
One or more host identifiers
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
            Headers  = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}