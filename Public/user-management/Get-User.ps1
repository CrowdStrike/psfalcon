function Get-User {
<#
.SYNOPSIS
    Retrieve user identifiers or usernames
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER NAMES
    Retrieve usernames (typically email addresses) rather than user identifiers
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RetrieveUserUUIDsByCID')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'RetrieveEmailsByCID',
            Mandatory = $true)]
        [switch] $Names,

        [Parameter(
            ParameterSetName = 'RetrieveUserUUIDsByCID',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'RetrieveUserUUIDsByCID',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RetrieveUserUUIDsByCID', 'RetrieveUser', 'RetrieveUserUUID', 'RetrieveEmailsByCID')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $PSCmdlet.ParameterSetName
                Entity = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = 'UserIds'
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}
