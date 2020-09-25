function Get-Session {
<#
.SYNOPSIS
    Retrieve Real-time Response sessions
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER QUEUE
    Lists information about sessions in the offline queue
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RTR-ListAllSessions')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'RTR-ListQueuedSessions',
            Mandatory = $true)]
        [switch] $Queue,

        [Parameter(
            ParameterSetName = 'RTR-ListAllSessions',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'RTR-ListAllSessions',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RTR-ListAllSessions', 'RTR-ListSessions', 'RTR-ListQueuedSessions')

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
                'Queue' {
                    $Param.Entity = $Endpoints[2]
                    $Param['Modifier'] = 'Queue'
                }
                'Detailed' {
                    $Param['Detailed'] = 'SessionIds'
                }
                'All' {
                    $Param['All'] = $true
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}