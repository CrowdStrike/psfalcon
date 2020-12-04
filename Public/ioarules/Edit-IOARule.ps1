function Edit-IOARule {
    <#
    .SYNOPSIS
        Modify a custom Indicator of Attack rule
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/update-rules')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('ioarules/update-rules')
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
                Format-Param -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}