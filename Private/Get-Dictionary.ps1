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
    }
    process {
        # Create parameters for each Falcon endpoint
        foreach ($Endpoint in $Falcon.Endpoint($Endpoints)) {
            foreach ($Param in $Endpoint.parameters) {
                # Convert 'type' to PowerShell type
                $PSType = switch ($Param.Type) {
                    'array' {
                        [array]
                    }
                    'bool' {
                        [bool]
                    }
                    'hashtable' {
                        [hashtable]
                    }
                    'int' {
                        [int]
                    }
                    'switch' {
                        [switch]
                    }
                    default {
                        [string]
                    }
                }
                if (-not($Dynamic.($Param.Dynamic))) {
                    # Create collection
                    $Collection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

                    # Create parameter
                    $Attribute = New-Object System.Management.Automation.ParameterAttribute

                    # Set base parameter attributes
                    $Attribute.ParameterSetName = $Endpoint.Name
                    $Attribute.Mandatory = $Param.Required

                    if ($Param.Description) {
                        # Set description
                        $Attribute.HelpMessage = $Param.Description
                    }
                    # Add attribute to collection
                    $Collection.Add($Attribute)

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
                        # Set ValidateRange when min/max is populated and parameter type is 'int'
                        $ValidRange = New-Object Management.Automation.ValidateRangeAttribute(
                            $Param.Min, $Param.Max)
                        $Collection.Add($ValidRange)
                    } elseif (($PSType -eq [string]) -and ($Param.Min -and $Param.Max)) {
                        # Set ValidateLength when min/max is populated and parameter type is 'string'
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
                } else {
                    # Add duplicate parameter as new attribute within existing dictionary
                    $Attribute = New-Object System.Management.Automation.ParameterAttribute
                    $Attribute.ParameterSetName = $Endpoint.Name
                    $Attribute.Mandatory = $Param.Required

                    $Dynamic.($Param.Dynamic).Attributes.add($Attribute)
                }
            }
        }
        # Output dynamic parameters
        return $Dynamic
    }
}