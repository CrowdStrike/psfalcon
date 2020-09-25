function Edit-HostGroup {
<#
.SYNOPSIS
    Edit Host Groups
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER ARRAY
    An array containing multiple groups to update in a single request
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'updateHostGroups')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'Array',
            HelpMessage = 'An array containing multiple groups to update in a single request',
            Mandatory = $true)]
        [array] $Array,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('updateHostGroups')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ($Array) {
                # Build body from array
                $Param = @{
                    Endpoint = $Endpoints[0]
                    Body = @{ resources = $Array }
                }
                # Convert Body to Json
                Format-Param $Param

                # Make request
                Invoke-Endpoint @Param
            } else {
                # Evaluate input and make request
                Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
            }
        }
    }
}
