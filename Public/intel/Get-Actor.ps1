function Get-Actor {
<#
.SYNOPSIS
    Search for threat actors
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
    [CmdletBinding(DefaultParameterSetName = 'QueryIntelActorIds')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'QueryIntelActorEntities',
            Mandatory = $true,
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = 'QueryIntelActorEntities')]
        [Parameter(
            ParameterSetName = 'QueryIntelActorIds',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QueryIntelActorIds', 'GetIntelActorEntities', 'QueryIntelActorEntities')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('QueryIntelActorEntities')
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