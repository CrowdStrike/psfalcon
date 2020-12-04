function Receive-Rule {
    <#
    .SYNOPSIS
        Download a zip file containing a threat intelligence ruleset
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'intel/GetIntelRuleFile')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('intel/GetIntelRuleFile', 'intel/GetLatestIntelRuleFile')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $PSCmdlet.ParameterSetName -Dynamic $Dynamic
        }
    }
}