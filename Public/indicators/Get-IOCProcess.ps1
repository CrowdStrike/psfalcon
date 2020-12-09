function Get-IOCProcess {
    <#
    .SYNOPSIS
        Search for processes associated with a custom IOC
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'indicators/ProcessesRanOn')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('indicators/ProcessesRanOn')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $DetailCmd = 'Get-FalconProcess'
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
                'All' {
                    $Param['All'] = $true
                }
            }
            $Request = Invoke-Request @Param
            if ($Request -and $PSBoundParameters.Detailed) {
                & $DetailCmd -ProcessIds $Request
            }
            else {
                $Request
            }
        }
    }
}