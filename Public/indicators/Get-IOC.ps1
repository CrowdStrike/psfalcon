function Get-IOC {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'indicators/QueryIOCs')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('indicators/QueryIOCs', 'indicators/GetIOC')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
                Dynamic = $Dynamic
            }
            if (($PSBoundParameters.Keys.count -eq 3) -and ($PSBoundParameters.Type -and
            $PSBoundParameters.Value -and $PSBoundParameters.Detailed)) {
                $PSBoundParameters.Remove('Detailed')
            }
            if (($PSBoundParameters.Keys.count -eq 2) -and ($PSBoundParameters.Type -and
            $PSBoundParameters.Value)) {
                $Param.Query = $Endpoints[1]
            }
            $Request = Invoke-Request @Param
            if ($Request -and $PSBoundParameters.Detailed) {
                foreach ($Item in $Request) {
                    & $MyInvocation.MyCommand.Name -Type $Item.Split(':')[0] -Value $Item.Split(':')[1]
                }
            }
            else {
                $Request
            }
        }
    }
}