function Get-HostGroup {
<#
.SYNOPSIS
    Search for Host Groups and their members
.PARAMETER MEMBERS
    Retrieve members assigned to policies
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'queryHostGroups')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'queryGroupMembers',
            Mandatory = $true)]
        [Parameter(
            ParameterSetName = 'queryCombinedGroupMembers',
            Mandatory = $true)]
        [switch] $Members,

        [Parameter(
            ParameterSetName = 'queryCombinedGroupMembers',
            Mandatory = $true)]
        [Parameter(
            ParameterSetName = 'queryCombinedHostGroups',
            HelpMessage = 'Retrieve detailed information',
            Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = 'queryHostGroups')]
        [Parameter(ParameterSetName = 'queryGroupMembers')]
        [Parameter(ParameterSetName = 'queryCombinedGroupMembers')]
        [Parameter(
            ParameterSetName = 'queryCombinedHostGroups',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('queryHostGroups', 'getHostGroups', 'queryCombinedHostGroups',
            'queryGroupMembers', 'queryCombinedGroupMembers')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('queryCombinedHostGroups',
                'queryCombinedGroupMembers')
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
                Entity = $Endpoints[1]
                Dynamic = $Dynamic
            }
            if ($All) {
                $Param['All'] = $true
            }
            if ($Detailed) {
                $Param['Detailed'] = 'Combined'
                $Param.Query = $Endpoints[2]
            }
            if ($Members) {
                $Param['Modifier'] = 'Members'

                if ($Detailed) {
                    $Param.Query = $Endpoints[4]
                } else {
                    $Param.Query = $Endpoints[3]
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}