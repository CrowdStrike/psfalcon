function Send-Script {
<#
.SYNOPSIS
    Upload a script to use with the Real-time Response 'runscript' command
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RTR-CreateScripts')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RTR-CreateScripts')

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
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ((Test-Path $Dynamic.Path.Value) -eq $false) {
                # Output exception for invalid file path
                throw "Cannot find path '$($Dynamic.Path.Value)' because it does not exist."
            }
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
