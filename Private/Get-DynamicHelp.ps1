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
        [Parameter(Mandatory = $true)]
        [array] $Command,

        [Parameter()]
        [array] $Exclusions
    )
    begin {
        $Defaults = @('Help', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
            'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')
        $ParamSets = foreach ($Set in ((Get-Command $Command).ParameterSets | Where-Object {
            ($_.name -ne 'DynamicHelp') -and ($Exclusions -notcontains $_.name) })) {
            $Endpoint = $Falcon.Endpoint($Set.Name)
            @{
                $Set.Name = @{
                    Description = "$($Endpoint.Description)"
                    Permission  = "$($Endpoint.Permission)"
                    Parameters  = ($Set.Parameters | Where-Object { $Defaults -notcontains $_.name }).foreach{
                        $Parameter = [ordered] @{
                            Name        = $_.Name
                            Type        = $_.ParameterType.name
                            Required    = $_.IsMandatory
                            Description = $_.HelpMessage
                        }
                        if ($_.Position -gt 0) {
                            $Parameter['Position'] = $_.Position
                        }
                        foreach ($Attribute in @('ValidValues', 'RegexPattern', 'MinLength', 'MaxLength',
                            'MinRange', 'MaxRange')) {
                            $Name = switch -Regex ($Attribute) {
                                'ValidValues' { 'Accepted' }
                                'RegexPattern' { 'Pattern' }
                                '(MinLength|MinRange)' { 'Minimum' }
                                '(MaxLength|MaxRange)' { 'Maximum' }
                            }
                            if ($_.Attributes.$Attribute) {
                                $Value = if ($_.Attributes.$Attribute -is [array]) {
                                    $_.Attributes.$Attribute -join ', '
                                }
                                else {
                                    $_.Attributes.$Attribute
                                }
                                $Parameter[$Name] = $Value
                            }
                        }
                        $Parameter
                    }
                }
            }
        }
    }
    process {
        foreach ($Set in $ParamSets.Keys) {
            $Permission = if ($ParamSets.$Set.Permission) {
                "Requires $($ParamSets.$Set.Permission)"
            }
            else {
                "No permissions required"
            }
            if ($ParamSets.$Set.Description) {
                "`n# $($ParamSets.$Set.Description)" +
                "`n  $($Permission)"
            }
            if ($ParamSets.$Set.Parameters) {
                foreach ($Parameter in $ParamSets.$Set.Parameters) {
                    if ($Parameter.Name) {
                        $Label = "`n  -$($Parameter.Name) [$($Parameter.Type)]"
                        if ($Parameter.Required -eq $true) {
                            $Label += " <Required>"
                        }
                        $Label + "`n    $($Parameter.Description)"
                    }
                    foreach ($Pair in ($Parameter.GetEnumerator() | Where-Object { $_.Key -notmatch
                        '(Name|Type|Required|Description)' })) {
                        "      $($Pair.Key) : $($Pair.Value)"
                    }
                }
            }
        }
        "`n"
    }
}