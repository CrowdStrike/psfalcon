function Get-DynamicHelp {
<#
.SYNOPSIS
    Outputs documentation about commands
.PARAMETER COMMAND
    PSFalcon Command name(s)
.PARAMETER EXCLUSIONS
    Falcon endpoint names to exclude from results
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [array] $Command,

        [Parameter(Position = 2)]
        [array] $Exclusions
    )
    begin {
        # List of PowerShell function parameters names (plus Help) to exclude from results
        $Defaults = @('Help', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
            'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable',
            'OutBuffer', 'PipelineVariable')

        # Capture parameter details
        $ParamDetail = (Get-Command $Command).ParameterSets.Parameters | Where-Object Name -notin $Defaults |
            Select-Object Name, ParameterType, IsMandatory, Attributes | Sort-Object { $_.Attributes.Position }
    }
    process {
        # Description for each endpoint, except those defined by $Exclusions
        foreach ($Endpoint in (($ParamDetail.Attributes.ParameterSetName | Group-Object).Name |
            Where-Object { $_ -notin $Exclusions })) {

            # Build example header text
            $HeaderText = "`n"

            if ($Falcon.Endpoint($Endpoint).Description) {
                # Add endpoint description
                $HeaderText += "  $($Falcon.Endpoint($Endpoint).Description)"
            }
            if ($Falcon.Endpoint($Endpoint).Permission) {
                # Add permission
                $HeaderText += "`n    Requires $((($Falcon.Endpoint($Endpoint)).Permission))"
            }
            # Output header text
            $HeaderText

            # Collect parameters for each endpoint
            $EndpointParam = $ParamDetail | Where-Object { $_.Attributes.ParameterSetName -eq $Endpoint } |
                Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 } |
                Sort-Object { $_.Attributes.Position }

            $EndpointParam | Sort-Object IsMandatory -Descending | ForEach-Object {
                # Collect parameter name and type
                $ParamText = "`n    -$($_.Name) [$($_.ParameterType.Name)]"

                if ($_.IsMandatory) {
                    # Add required status
                    $ParamText += " (Required)"
                }
                if ($_.Attributes.ValidValues) {
                    # Add possible input values
                    $ParamText += " <$($_.Attributes.ValidValues -join ', ')>"
                }
                if ($_.Attributes.MinRange -and $_.Attributes.MaxRange) {
                    # Add range values
                    $ParamText += " <$($_.Attributes.MinRange)-$($_.Attributes.MaxRange)>"
                }
                if ($_.Attributes.HelpMessage) {
                    # Add description
                    $ParamText += "`n    $($_.Attributes.HelpMessage)"
                }
                # Output parameter text
                $ParamText
            }
        }
        ""
    }
}