function Get-FirewallField {
    <#
    .SYNOPSIS
        Search for firewall field specifications
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/query-firewall-fields')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('fwmgr/query-firewall-fields', 'fwmgr/get-firewall-fields')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
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
