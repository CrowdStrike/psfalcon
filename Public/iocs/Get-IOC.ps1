function Get-IOC {
<#
.SYNOPSIS
    Search for Custom IOCs
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER COUNT
    Retrieve the total number of hosts that have observed a custom IOC
.PARAMETER HOSTS
    Retrieve host identifiers for hosts that have observed a custom IOC
.PARAMETER PROCESSES
    Retrieve process identifiers for a host that has observed a custom IOC
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'QueryIOCs')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DevicesCount',
            Mandatory = $true)]
        [switch] $Count,

        [Parameter(
            ParameterSetName = 'DevicesRanOn',
            Mandatory = $true)]
        [switch] $Hosts,

        [Parameter(
            ParameterSetName = 'ProcessesRanOn',
            Mandatory = $true)]
        [switch] $Processes,

        [Parameter(ParameterSetName = 'ProcessesRanOn')]
        [Parameter(ParameterSetName = 'DevicesRanOn')]
        [Parameter(
            ParameterSetName = 'QueryIOCs',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QueryIOCs', 'GetIOC', 'DevicesCount', 'DevicesRanOn', 'ProcessesRanOn')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'Count' {
                    $Param.Query = $Endpoints[2]
                    $Param['Modifier'] = 'Count'
                }
                'Hosts' {
                    $Param.Query = $Endpoints[3]
                    $Param['Modifier'] = 'Hosts'
                }
                'Processes' {
                    $Param.Query = $Endpoints[4]
                    $Param['Modifier'] = 'Processes'
                }
                'All' {
                    $Param['All'] = $true
                }
            }
            if ((-not($Param.Modifier)) -and ($Dynamic.Type.value -and $Dynamic.Value.value)) {
                # Switch from 'QueryIOCs' to 'GetIOC' if Type and Value are input
                $Param.Query = $Endpoints[1]
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}