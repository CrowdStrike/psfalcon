function Open-Stream {
<#
.SYNOPSIS
    Open an Event Stream and output to a Json file
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'OpenStream')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('OpenStream')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } elseif (($PSVersionTable.PSVersion.Major -lt 6) -or ($IsWindows -eq $true)) {
            # Open stream
            $Stream = Get-FalconStream -AppId 'PSFalcon' -Format json

            if ($Stream.resources) {
                # Create parameters from stream
                $ArgumentList =
                "try {
                    `$Param = @{
                        Uri = '$($Stream.resources.datafeedURL)'
                        Method = 'get'
                        Headers = @{
                            accept = 'application/json'
                            authorization = 'Token $($Stream.resources.sessionToken.token)'
                        }
                        OutFile = '$($pwd)\Stream_$(Get-Date -Format FileDateTime).json'
                    }
                    Invoke-WebRequest @Param
                } catch {
                    Write-Output $_ | Out-File `$FilePath
                }"
                # Launch PowerShell window and output results to working directory
                Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList
            } else {
                $Stream
            }
        } else {
            # Output exception if run on non-Windows devices
            throw "This command is only compatible with PowerShell on Windows"
        }
    }
}