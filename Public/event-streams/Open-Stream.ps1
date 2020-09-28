function Open-Stream {
<#
.SYNOPSIS
    Open an Event Stream and output to a Json file
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding()]
    [OutputType()]
    param()
    process {
        if (($PSVersionTable.PSVersion.Major -lt 6) -or ($IsWindows -eq $true)) {
            $Stream = Get-FalconStream -AppId 'PSFalcon' -Format json

            if ($Stream.resources) {
                # Create parameters from initialization of stream
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
            throw "This command is only compatible with PowerShell on Windows"
        }
    }
}