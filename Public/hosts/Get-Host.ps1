function Get-Host {
<#
.SYNOPSIS
    Search for hosts
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HIDDEN
    Search for hidden hosts
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'QueryDevicesByFilterScroll')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'QueryHiddenDevices',
            HelpMessage = 'Search for hidden hosts',
            Mandatory = $true)]
        [switch] $Hidden,

        [Parameter(ParameterSetName = 'QueryDevicesByFilterScroll')]
        [Parameter(
            ParameterSetName = 'QueryHiddenDevices',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = 'QueryDevicesByFilterScroll')]
        [Parameter(
            ParameterSetName = 'QueryHiddenDevices',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QueryDevicesByFilterScroll', 'GetDeviceDetails', 'QueryHiddenDevices')

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
                Entity = $Endpoints[1]
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
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}
