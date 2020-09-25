function Get-TokenEvent {
<#
.SYNOPSIS
    Search for installation token audit events
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
    [CmdletBinding(DefaultParameterSetName = 'audit-events-query')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'audit-events-query',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'audit-events-query',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('audit-events-query', 'audit-events-read')

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
                    $Param['Detailed'] = 'EventIds'
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}