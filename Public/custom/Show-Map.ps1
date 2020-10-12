function Show-Map {
<#
.SYNOPSIS
    Launch the Indicator Graph in a browser window
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'CustomShowMap')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('CustomShowMap')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        # Set UI address
        $FalconUI = "$($Falcon.Hostname -replace 'api', 'falcon')"
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input
            $Param = Get-Param $Endpoints[0] $Dynamic

            $Param.Query = ($Param.Query).foreach{
                # Split into type/value
                $Split = $_ -split ':'

                # Update type to hash/ip/domain
                $Type = switch ($Split[0]) {
                    'sha256' { 'hash' }
                    'md5' { 'hash' }
                    'ipv4' { 'ip' }
                    'ipv6' { 'ip' }
                    'domain' { 'domain' }
                }
                # Output corrected value
                "$($Type):'$($Split[1])'"
            }
            # Launch browser window to load Indicator Graph
            Start-Process "$($FalconUI)$($Falcon.Endpoint($Endpoints[0]).path)$($Param.Query -join ',')"
        }
    }
}