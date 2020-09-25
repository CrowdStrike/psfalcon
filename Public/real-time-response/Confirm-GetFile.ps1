function Confirm-GetFile {
<#
.SYNOPSIS
    Lists files retrieved with 'get' during a Real-time Response session
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RTR-ListFiles')]
    [OutputType()]
    param(
        [Parameter(ParameterSetName = 'BatchGetCmdStatus')]
        [Parameter(
            ParameterSetName = 'RTR-ListFiles',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RTR-ListFiles', 'BatchGetCmdStatus')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $PSCmdlet.ParameterSetName
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
            }
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}
