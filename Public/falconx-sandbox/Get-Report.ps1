function Get-Report {
<#
.SYNOPSIS
    Search for sandbox submission analysis reports
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER SUMMARY
    Retrieve summary information
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'QueryReports')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'GetSummaryReports',
            Mandatory = $true)]
        [switch] $Summary,

        [Parameter(
            ParameterSetName = 'QueryReports',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'QueryReports',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('QueryReports', 'GetReports', 'GetSummaryReports')

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
                    $Param['Detailed'] = 'ReportIds'
                }
                'Summary' {
                    $Param.Entity = $Endpoints[2]
                    $Param['Modifier'] = 'Summary'
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}