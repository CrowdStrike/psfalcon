function Get-IOAExclusion {
    <#
    .SYNOPSIS
        Retrieve information about Indicator of Attack exclusions
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/queryIOAExclusionsv1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/queryIOAExclusionsV1', 'policy/GetIOAExclusionsv1')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = 'ExclusionIds'
                }
            }
            Invoke-Request @Param
        }
    }
}