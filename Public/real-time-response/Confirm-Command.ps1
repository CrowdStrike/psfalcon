function Confirm-Command {
<#
.SYNOPSIS
    Check the status of an executed Real-time Response command
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RTR-CheckCommandStatus')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'RTR-CheckCommandStatus',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RTR-CheckCommandStatus')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not($Dynamic.SequenceId.Value)) {
            # Set default SequenceId of 0
            $Dynamic.SequenceId.Value = 0
        }
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