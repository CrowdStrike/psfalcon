function Get-Installer {
<#
.SYNOPSIS
    Search for sensor installer packages
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'GetSensorInstallersByQuery')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'GetCombinedSensorInstallersByQuery',
            HelpMessage = 'Retrieve detailed information',
            Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = 'GetCombinedSensorInstallersByQuery')]
        [Parameter(
            ParameterSetName = 'GetSensorInstallersByQuery',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('GetSensorInstallersByQuery', 'GetSensorInstallersEntities',
            'GetCombinedSensorInstallersByQuery')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('GetCombinedSensorInstallersByQuery')
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