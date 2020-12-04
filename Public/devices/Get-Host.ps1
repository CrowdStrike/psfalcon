function Get-Host {
    <#
    .SYNOPSIS
        Search for hosts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'devices/QueryDevicesByFilterScroll')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('devices/QueryDevicesByFilterScroll', 'devices/GetDeviceDetails',
            'devices/QueryHiddenDevices')
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
                    $Param['Detailed'] = 'HostIds'
                }
                'Hidden' {
                    $Param.Query = $Endpoints[2]
                    $Param['Modifier'] = 'Hidden'
                }
            }
            Invoke-Request @Param
        }
    }
}
