function New-IOC {
    <#
    .SYNOPSIS
        Create custom IOCs
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'indicators/CreateIOC')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('indicators/CreateIOC', 'private/Array')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Max = 200
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif ($PSBoundParameters.Array) {
            for ($i = 0; $i -lt ($PSBoundParameters.Array).count; $i += $Max) {
                $Param = @{
                    Endpoint = $Endpoints[0]
                    Body     = $PSBoundParameters.Array[$i..($i + ($Max - 1))]
                }
                Format-Param -Param $Param
                Invoke-Endpoint @Param
            }
        }
        else {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            $Param.Body = @( $Param.Body )
            Format-Param -Param $Param
            Invoke-Endpoint @Param
        }
    }
}
