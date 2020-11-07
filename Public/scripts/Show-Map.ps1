function Show-Map {
    <#
    .SYNOPSIS
        Launch the Indicator Graph in a browser window
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'scripts/ShowMap')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('scripts/ShowMap')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $FalconUI = "$($Falcon.Hostname -replace 'api', 'falcon')"
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            $Param.Query = ($Param.Query).foreach{
                $Split = $_ -split ':'
                $Type = switch ($Split[0]) {
                    'sha256' { 'hash' }
                    'md5' { 'hash' }
                    'ipv4' { 'ip' }
                    'ipv6' { 'ip' }
                    'domain' { 'domain' }
                }
                "$($Type):'$($Split[1])'"
            }
            Start-Process "$($FalconUI)$($Falcon.Endpoint($Endpoints[0]).path)$($Param.Query -join ',')"
        }
    }
}