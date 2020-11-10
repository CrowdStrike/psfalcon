function Remove-IOAGroup {
    <#
    .SYNOPSIS
        Remove custom Indicator of Attack rule groups
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/delete-rule-groups')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('ioarules/delete-rule-groups')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.id)"
                }
                Invoke-Endpoint @Param
            }
        }
    }
}