function Get-IOAPlatform {
    <#
    .SYNOPSIS
        Search for available platforms for use with custom Indicators of Attack
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/query-platforms')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('ioarules/query-platforms', 'ioarules/get-platforms')
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
                    $Param['Detailed'] = 'PlatformIds'
                }
            }
            Invoke-Request @Param
        }
    }
}
