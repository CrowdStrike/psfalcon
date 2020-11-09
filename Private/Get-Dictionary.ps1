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
        [Parameter(Mandatory = $true)]
        [array] $Endpoints
    )
    begin {
        $Dynamic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        function Add-Parameter ($Param, $Endpoint) {
            $Attribute = New-Object System.Management.Automation.ParameterAttribute
            $Attribute.ParameterSetName = $Endpoint
            $Attribute.Mandatory = $Param.Required
            if ($Param.Description) {
                $Attribute.HelpMessage = $Param.Description
            }
            if ($Param.Position) {
                $Attribute.Position = $Param.Position
            }
            if ($Dynamic.($Param.Dynamic)) {
                $Dynamic.($Param.Dynamic).Attributes.add($Attribute)
            }
            else {
                $Collection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $Collection.Add($Attribute)
                $PSType = switch ($Param.Type) {
                    'array' { [array] }
                    'bool' { [bool] }
                    'hashtable' { [hashtable] }
                    'int' { [int] }
                    'switch' { [switch] }
                    default { [string] }
                }
                if ($Param.Mandatory -eq $false) {
                    $ValidEmpty = New-Object Management.Automation.ValidateNotNullOrEmptyAttribute
                    $Collection.Add($ValidEmpty)
                }
                if ($Param.Enum) {
                    $ValidSet = New-Object System.Management.Automation.ValidateSetAttribute($Param.Enum)
                    $ValidSet.IgnoreCase = $false
                    $Collection.Add($ValidSet)
                }
                if (($PSType -eq [int]) -and ($Param.Min -and $Param.Max)) {
                    $ValidRange = New-Object Management.Automation.ValidateRangeAttribute(
                        $Param.Min, $Param.Max)
                    $Collection.Add($ValidRange)
                }
                elseif (($PSType -eq [string]) -and ($Param.Min -and $Param.Max)) {
                    $ValidLength = New-Object System.Management.Automation.ValidateLengthAttribute(
                        $Param.Min, $Param.Max)
                    $Collection.Add($ValidLength)
                }
                if ($Param.Pattern) {
                    $ValidPattern = New-Object Management.Automation.ValidatePatternAttribute(
                        ($Param.Pattern).ToString())
                    $Collection.Add($ValidPattern)
                }
                if ($Param.Script) {
                    $ValidScript = New-Object Management.Automation.ValidateScriptAttribute([scriptblock]::Create(
                        $Param.Script))
                    if ($Param.ScriptError -and $ValidScript.ErrorMessage) {
                        $ValidScript.ErrorMessage = $Param.ScriptError
                    }
                    $Collection.Add($ValidScript)
                }
                $RunParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
                    $Param.Dynamic, $PSType, $Collection)
                $Dynamic.Add($Param.Dynamic, $RunParam)
            }
        }
    }
    process {
        foreach ($Endpoint in $Endpoints) {
            foreach ($Param in $Falcon.Endpoint($Endpoint).Parameters) {
                Add-Parameter $Param $Endpoint
            }
            foreach ($Param in ($Falcon.Endpoint('private/SharedParameters').Parameters |
                Where-Object { $_.ParameterSets -contains $Endpoint })) {
                Add-Parameter $Param $Endpoint
            }
        }
        $DynamicHelp = @{
            Dynamic = 'Help'
            Type = 'switch'
            Required = $true
            Description = 'Output dynamic help information'
        }
        Add-Parameter $DynamicHelp 'DynamicHelp'
        return $Dynamic
    }
}