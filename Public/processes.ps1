function Get-FalconProcess {
<#
.Synopsis
For the provided ProcessID retrieve the process details
.Parameter Ids
One or more process identifiers
.Role
iocs:read
#>
    [CmdletBinding(DefaultParameterSetName = '/processes/entities/processes/v1:get')]
    param(
        [Parameter(ParameterSetName = '/processes/entities/processes/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^pid:\w{32}:\d{1,}$')]
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