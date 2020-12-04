function Get-Report {
    <#
    .SYNOPSIS
        Search for sandbox submission analysis reports
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'falconx/QueryReports')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('falconx/QueryReports', 'falconx/GetReports', 'falconx/GetSummaryReports')
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
                    $Param['Detailed'] = 'ReportIds'
                }
                'Summary' {
                    $Param.Entity = $Endpoints[2]
                    $Param['Modifier'] = 'Summary'
                }
            }
            Invoke-Request @Param
        }
    }
}