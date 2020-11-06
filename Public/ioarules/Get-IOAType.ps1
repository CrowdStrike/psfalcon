function Get-IOAType {
    <#
    .SYNOPSIS
        Search for custom Indicator of Attack rule types
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/query-rule-types')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('ioarules/query-rule-types', 'ioarules/get-rule-types')
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
                    $Param['Detailed'] = 'TypeIds'
                }
            }
            Invoke-Request @Param
        }
    }
}