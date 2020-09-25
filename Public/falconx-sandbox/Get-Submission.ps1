function Get-Submission {
<#
.SYNOPSIS
    Search for sandbox submissions
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'QuerySubmissions')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'QuerySubmissions',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'QuerySubmissions',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QuerySubmissions', 'GetSubmissions')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
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
                    $Param['Detailed'] = 'SubmissionIds'
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}