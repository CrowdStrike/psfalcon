function Get-Dictionary {
<#
.SYNOPSIS
    Create a dynamic parameter dictionary
.PARAMETER ENDPOINTS
    Falcon endpoint name(s)
#>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.RuntimeDefinedParameterDictionary])]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [array] $Endpoints
    )
    begin {
        # Create dynamic parameter dictionary
        $Dynamic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        function Add-Parameter ($Param, $Endpoint) {
            # Create parameter
            $Attribute = New-Object System.Management.Automation.ParameterAttribute

            # Set base parameter attributes
            $Attribute.ParameterSetName = $Endpoint
            $Attribute.Mandatory = $Param.Required
            $Attribute.HelpMessage = $Param.Description

            if ($Param.Position) {
                $Attribute.Position = $Param.Position
            }
            if ($Dynamic.($Param.Dynamic)) {
                # Add attribute to existing collection
                $Dynamic.($Param.Dynamic).Attributes.add($Attribute)
            } else {
                # Create collection
                $Collection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

                # Add attribute to collection
                $Collection.Add($Attribute)

                # Convert 'type' to PowerShell type
                $PSType = switch ($Param.Type) {
                    'array' { [array] }
                    'bool' { [bool] }
                    'hashtable' { [hashtable] }
                    'int' { [int] }
                    'switch' { [switch] }
                    default { [string] }
                }
                if ($Param.Mandatory -eq $false) {
                    # Set ValidateNotNullOrEmpty when parameter is optional
                    $ValidEmpty = New-Object Management.Automation.ValidateNotNullOrEmptyAttribute
                    $Collection.Add($ValidEmpty)
                }
                if ($Param.Enum) {
                    # Set ValidateSet when enum is populated
                    $ValidSet = New-Object System.Management.Automation.ValidateSetAttribute($Param.Enum)
                    $ValidSet.IgnoreCase = $false
                    $Collection.Add($ValidSet)
                }
                if (($PSType -eq [int]) -and ($Param.Min -and $Param.Max)) {
                    # Set ValidateRange when min/max is populated and parameter type is [int]
                    $ValidRange = New-Object Management.Automation.ValidateRangeAttribute(
                        $Param.Min, $Param.Max)
                    $Collection.Add($ValidRange)
                } elseif (($PSType -eq [string]) -and ($Param.Min -and $Param.Max)) {
                    # Set ValidateLength when min/max is populated and parameter type is [string]
                    $ValidLength = New-Object System.Management.Automation.ValidateLengthAttribute(
                        $Param.Min, $Param.Max)
                    $Collection.Add($ValidLength)
                }
                if ($Param.Pattern) {
                    # Set ValidatePattern when pattern is populated
                    $ValidPattern = New-Object Management.Automation.ValidatePatternAttribute(
                        ($Param.Pattern).ToString())
                    $Collection.Add($ValidPattern)
                }
                # Add collection to runtime parameter
                $RunParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
                    $Param.Dynamic, $PSType, $Collection)

                # Add runtime parameter to dictionary
                $Dynamic.Add($Param.Dynamic, $RunParam)
            }
        }
    }
    process {
        foreach ($Endpoint in $Endpoints) {
            foreach ($Param in $Falcon.Endpoint($Endpoint).Parameters) {
                # Add parameters from each endpoint
                Add-Parameter $Param $Endpoint
            }
            foreach ($Param in ($Falcon.Endpoint('SharedParameters').Parameters |
            Where-Object { $_.ParameterSets -contains $Endpoint })) {
                # Add shared parameters
                Add-Parameter $Param $Endpoint
            }
        }
        # Add dynamic help parameter
        $DynamicHelp = @{
            Dynamic = 'Help'
            Type = 'switch'
            Required = $true
            Description = 'Output dynamic help information'
        }
        Add-Parameter $DynamicHelp 'DynamicHelp'

        # Output dynamic parameters
        return $Dynamic
    }
}