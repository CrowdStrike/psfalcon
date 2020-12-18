function Open-Stream {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
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
            try {
                $Stream = Get-FalconStream -AppId 'psfalcon' -Format json
                if ($Stream) {
                    $ArgumentList =
                    "try {
                        `$Param = @{
                            Uri = '$($Stream.datafeedURL)'
                            Method = 'get'
                            Headers = @{
                                accept = 'application/json'
                                authorization = 'Token $($Stream.sessionToken.token)'
                            }
                            OutFile = '$($pwd)\Stream_$(Get-Date -Format FileDateTime).json'
                        }
                        Invoke-WebRequest @Param
                    } catch {
                        Write-Output `$_ | Out-File `$FilePath
                    }"
                    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList
                }
            }
            catch {
                $_
            }
        }
        else {
            throw "This command is only compatible with PowerShell on Windows"
        }
    }
}