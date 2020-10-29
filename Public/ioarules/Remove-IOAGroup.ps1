function Remove-IOAGroup {
<#
.SYNOPSIS
    Remove custom Indicator of Attack rule groups
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/delete-rule-groups')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('ioarules/delete-rule-groups')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}