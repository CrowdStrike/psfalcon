function Get-Submission {
    <#
    .SYNOPSIS
        Search for sandbox submissions
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'falconx/QuerySubmissions')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('falconx/QuerySubmissions', 'falconx/GetSubmissions')
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
                    $Param['Detailed'] = 'SubmissionIds'
                }
            }
            Invoke-Request @Param
        }
    }
}