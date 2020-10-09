function Get-IOC {
<#
.SYNOPSIS
    Search for Custom IOCs
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'QueryIOCs')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QueryIOCs', 'GetIOC', 'DevicesCount', 'DevicesRanOn', 'ProcessesRanOn')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input and make request
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
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
                # Switch from 'QueryIOCs' to 'GetIOC' if Type and Value are input
                $Param.Query = $Endpoints[1]
            }
            Invoke-Request @Param
        }
    }
}