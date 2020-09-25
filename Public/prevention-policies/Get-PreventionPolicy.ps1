function Get-PreventionPolicy {
<#
.SYNOPSIS
    Search for Prevention policies and their members
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
    [CmdletBinding(DefaultParameterSetName = 'queryPreventionPolicies')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'queryPreventionPolicyMembers',
            Mandatory = $true)]
        [Parameter(
            ParameterSetName = 'queryCombinedPreventionPolicyMembers',
            Mandatory = $true)]
        [switch] $Members,

        [Parameter(
            ParameterSetName = 'queryCombinedPreventionPolicies',
            Mandatory = $true)]
        [Parameter(
            ParameterSetName = 'queryCombinedPreventionPolicyMembers',
            HelpMessage = 'Retrieve detailed information',
            Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = 'queryPreventionPolicies')]
        [Parameter(ParameterSetName = 'queryCombinedPreventionPolicies')]
        [Parameter(ParameterSetName = 'queryPreventionPolicyMembers')]
        [Parameter(
            ParameterSetName = 'queryCombinedPreventionPolicyMembers',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('queryPreventionPolicies', 'getPreventionPolicies', 'queryCombinedPreventionPolicies',
            'queryPreventionPolicyMembers', 'queryCombinedPreventionPolicyMembers')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('queryCombinedPreventionPolicies',
                'queryCombinedPreventionPolicyMembers')
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