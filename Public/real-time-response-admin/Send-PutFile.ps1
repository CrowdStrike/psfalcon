function Send-PutFile {
<#
.SYNOPSIS
    Upload a file to use with the Real-time Response 'put' command
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RTR-CreatePut-Files')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RTR-CreatePut-Files')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        if ($Dynamic.Path.Value -match '^\.') {
            # Convert relative path to absolute path
            $Dynamic.Path.Value = $Dynamic.Path.Value -replace '^\.', $pwd
        }
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ((Test-Path $Dynamic.Path.Value) -eq $false) {
                throw "Cannot find path '$($Dynamic.Path.Value)' because it does not exist."
            }
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
