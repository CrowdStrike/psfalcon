function Get-DynamicHelp {
<#
.SYNOPSIS
    Outputs documentation about commands
.PARAMETER COMMAND
    PSFalcon command name(s)
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
        # PowerShell default parameter names (plus Help) to exclude from results
        $Defaults = @('Help', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
        'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')

        # Capture parameter set information
        $ParamSets = foreach ($Set in ((Get-Command $Command).ParameterSets | Where-Object {
        ($_.name -ne 'DynamicHelp') -and ($Exclusions -notcontains $_.name)})) {
            # Set target endpoint
            $Endpoint = $Falcon.Endpoint($Set.Name)

            @{
                # Create ParameterSet hashtable
                $Set.Name = @{
                    Description = "$($Endpoint.Description)"
                    Permission = "$($Endpoint.Permission)"
                    Parameters = ($Set.Parameters | Where-Object { $Defaults -notcontains $_.name }).foreach{
                        # Include parameters not listed in $Defaults
                        $Parameter = [ordered] @{
                            Name = $_.Name
                            Type = $_.ParameterType.name
                            Required = $_.IsMandatory
                            Description = $_.HelpMessage
                        }
                        # Add ValidateSet, ValidateLength and ValidateRange values
                        foreach ($Attribute in @('ValidValues', 'RegexPattern', 'MinLength', 'MaxLength',
                        'MinRange', 'MaxRange')) {
                            $Name = switch -Regex ($Attribute) {
                                # Convert field names into friendly descriptors
                                'ValidValues' { 'Accepted' }
                                'RegexPattern' { 'Pattern' }
                                '(MinLength|MinRange)' { 'Minimum' }
                                '(MaxLength|MaxRange)' { 'Maximum' }
                            }
                            if ($_.Attributes.$Attribute) {
                                $Value = if ($_.Attributes.$Attribute -is [array]) {
                                    # Convert [array] to [string]
                                    $_.Attributes.$Attribute -join ', '
                                } else {
                                    $_.Attributes.$Attribute
                                }
                                $Parameter[$Name] = $Value
                            }
                        }
                        # Add parameter to array
                        $Parameter
                    }
                }
            }
        }
    }
    process {
        foreach ($Set in $ParamSets.Keys) {
            # Capture permissions for endpoint
            $Permission = if ($ParamSets.$Set.Permission) {
                "Requires $($ParamSets.$Set.Permission)"
            } else {
                "No permissions required"
            }
            # Output description and permission
            "`n# $($ParamSets.$Set.Description)" +
            "`n  $($Permission)"

            if ($ParamSets.$Set.Parameters) {
                # Output parameters
                foreach ($Parameter in $ParamSets.$Set.Parameters) {
                    if ($Parameter.Name) {
                        # Output name, type, required status and description
                        $Label = "`n  -$($Parameter.Name) [$($Parameter.Type)]"

                        if ($Parameter.Required -eq $true) {
                            $Label += " <Required>"
                        }
                        $Label + "`n    $($Parameter.Description)"
                    }
                    foreach ($Pair in ($Parameter.GetEnumerator() | Where-Object { $_.Key -notmatch
                    '(Name|Type|Required|Description)'})) {
                        # Output parameter attributes
                        "      $($Pair.Key) : $($Pair.Value)"
                    }
                }
            }
        }
        # Output blank line
        "`n"
    }
}