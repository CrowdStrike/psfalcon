function Get-FirewallField {
<#
.SYNOPSIS
    Search for firewall field specifications
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'query-firewall-fields')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('query-firewall-fields', 'get-firewall-fields')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input and make request
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
                    $Param['Detailed'] = 'FieldIds'
                }
            }
            Invoke-Request @Param
        }
    }
}
