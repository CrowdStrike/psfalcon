function Get-IOASeverity {
    <#
    .SYNOPSIS
        Search for available patterns for use with custom Indicators of Attack
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/query-patterns')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('ioarules/query-patterns', 'ioarules/get-patterns')
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
                    $Param['Detailed'] = 'SeverityIds'
                }
            }
            Invoke-Request @Param
        }
    }
}
