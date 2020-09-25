function Invoke-MalQuery {
<#
.SYNOPSIS
    Perform a MalQuery search
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER FUZZY
    Perform a fuzzy search
.PARAMETER HUNT
    Schedule a YARA-based search
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'PostMalQueryExactSearchV1')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'PostMalQueryFuzzySearchV1',
            Mandatory = $true)]
        [switch] $Fuzzy,

        [Parameter(
            ParameterSetName = 'PostMalQueryHuntV1',
            Mandatory = $true)]
        [switch] $Hunt,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('PostMalQueryExactSearchV1', 'PostMalQueryFuzzySearchV1', 'PostMalQueryHuntV1')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input
            $Param = Get-Param $PSCmdlet.ParameterSetName $Dynamic

            if ($Param.Body.options) {
                # Convert options from array to hashtable
                $Param.Body.options = $Param.Body.options[0]
            }
            # Convert to Json
            Format-Param $Param

            # Make request
            Invoke-Endpoint @Param
        }
    }
}