function Set-PreventionPrecedence {
    <#
    .SYNOPSIS
        Set the precedence of Prevention policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/setPreventionPoliciesPrecedence')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/setPreventionPoliciesPrecedence')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}