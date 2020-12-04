function Get-Actor {
    <#
    .SYNOPSIS
        Search for threat actors
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'intel/QueryIntelActorIds')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('intel/QueryIntelActorIds', 'intel/GetIntelActorEntities', 'intel/QueryIntelActorEntities')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @('intel/QueryIntelActorEntities')
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
                    $Param['Detailed'] = 'Combined'
                    $Param.Query = $Endpoints[2]
                }
            }
            Invoke-Request @Param
        }
    }
}