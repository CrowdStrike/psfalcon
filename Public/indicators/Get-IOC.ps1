function Get-IOC {
    <#
    .SYNOPSIS
        Search for Custom IOCs
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'indicators/QueryIOCs')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('indicators/QueryIOCs', 'indicators/GetIOC', 'indicators/DevicesCount',
            'indicators/DevicesRanOn', 'indicators/ProcessesRanOn')
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
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'TotalCount' {
                    $Param.Query = $Endpoints[2]
                    $Param['Modifier'] = 'TotalCount'
                }
                'Observed' {
                    $Param.Query = $Endpoints[3]
                    $Param['Modifier'] = 'Observed'
                }
                'Processes' {
                    $Param.Query = $Endpoints[4]
                    $Param['Modifier'] = 'Processes'
                }
                'All' {
                    $Param['All'] = $true
                }
            }
            if (-not($Param.Modifier) -and ($PSBoundParameters.Type -and $PSBoundParameters.Value)) {
                $Param.Query = $Endpoints[1]
            }
            Invoke-Request @Param
        }
    }
}