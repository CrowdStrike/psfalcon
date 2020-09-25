function Get-Indicator {
<#
.SYNOPSIS
    Search for threat intelligence indicators
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'QueryIntelIndicatorIds')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'QueryIntelIndicatorEntities',
            Mandatory = $true,
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = 'QueryIntelIndicatorEntities')]
        [Parameter(
            ParameterSetName = 'QueryIntelIndicatorIds',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QueryIntelIndicatorIds', 'GetIntelIndicatorEntities', 'QueryIntelIndicatorEntities')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('QueryIntelIndicatorEntities')
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
                Entity = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = 'Combined'
                    $Param.Query = $Endpoints[2]
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}