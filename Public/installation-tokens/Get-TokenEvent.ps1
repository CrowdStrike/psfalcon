function Get-TokenEvent {
    <#
    .SYNOPSIS
        Search for installation token audit events
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'installation-tokens/audit-events-query')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('installation-tokens/audit-events-query', 'installation-tokens/audit-events-read')
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
                    $Param['Detailed'] = 'EventIds'
                }
            }
            Invoke-Request @Param
        }
    }
}