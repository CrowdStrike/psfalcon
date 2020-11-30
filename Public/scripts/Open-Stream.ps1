function Open-Stream {
    <#
    .SYNOPSIS
        Open an Event Stream and output to a Json file
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'scripts/OpenStream')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('scripts/OpenStream')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif (($PSVersionTable.PSVersion.Major -lt 6) -or ($IsWindows -eq $true)) {
            $Stream = Get-FalconStream -AppId 'psfalcon' -Format json
            if ($Stream.resources) {
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
                Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList
            }
            else {
                $Stream
            }
        }
        else {
            throw "This command is only compatible with PowerShell on Windows"
        }
    }
}