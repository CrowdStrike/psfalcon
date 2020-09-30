function Get-HostGroup {
<#
.SYNOPSIS
    Search for Host Groups and their members
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'queryHostGroups')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('queryHostGroups', 'getHostGroups', 'queryCombinedHostGroups',
            'queryGroupMembers', 'queryCombinedGroupMembers')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('queryCombinedHostGroups',
                'queryCombinedGroupMembers')
        } else {
            # Evaluate input and make request
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
                Entity = $Endpoints[1]
                Dynamic = $Dynamic
            }
            if ($PSBoundParameters.All) {
                $Param['All'] = $true
            }
            if ($PSBoundParameters.Detailed) {
                $Param['Detailed'] = 'Combined'
                $Param.Query = $Endpoints[2]
            }
            if ($PSBoundParameters.Members) {
                $Param['Modifier'] = 'Members'

                if ($PSBoundParameters.Detailed) {
                    $Param.Query = $Endpoints[4]
                } else {
                    $Param.Query = $Endpoints[3]
                }
            }
            Invoke-Request @Param
        }
    }
}