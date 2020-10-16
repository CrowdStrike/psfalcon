function Invoke-Request {
<#
.SYNOPSIS
    Determines request type and submits input to Invoke-Loop or Invoke-Endpoint
.PARAMETER COMMAND
    PSFalcon command calling Invoke-Request [required for -All and -Detailed]
.PARAMETER QUERY
    The Falcon endpoint that is used for 'query' operations
.PARAMETER ENTITY
    The Falcon endpoint that is used for 'get' operations
.PARAMETER DYNAMIC
    A runtime parameter dictionary to search for input values
.PARAMETER DETAILED
    Type of request used to retrieve detailed information
.PARAMETER MODIFIER
    The name of a switch parameter used to modify a command when using Invoke-Loop
.PARAMETER ALL
    Toggle the use of Invoke-Loop
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter()]
        [string] $Command,

        [Parameter(Mandatory = $true)]
        [string] $Query,

        [Parameter()]
        [string] $Entity,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic,

        [Parameter()]
        [string] $Detailed,

        [Parameter()]
        [string] $Modifier,

        [Parameter()]
        [switch] $All
    )
    process {
        if ($All) {
            $LoopParam = @{
                Command = $Command
                Param = Get-LoopParam $Dynamic
            }
            switch ($Detailed) {
                'Combined' {
                    # Set detail switch to use 'Combined' endpoints
                    $LoopParam.Param['Detailed'] = $true
                }
                default {
                    # Pass identifier parameter name to use 'Entity' endpoints
                    $LoopParam['Detailed'] = $Detailed
                }
            }
            if ($Modifier) {
                # Add modifier switch to command parameters
                $LoopParam.Param[$Modifier] = $true
            }
            # Repeat requests until all results are retrieved
            Invoke-Loop @LoopParam
        } else {
            # Set target endpoint
            $Endpoint = if (($Dynamic.values | Where-Object IsSet).Attributes.ParameterSetName -eq $Entity) {
                # Use 'Entity' if ParameterSetName matches $Entity
                $Entity
            } else {
                # Use 'Query'
                $Query
            }
            foreach ($Param in (Get-Param $Endpoint $Dynamic)) {
                # Convert body to Json
                Format-Param $Param

                if ($Detailed -and $Detailed -ne 'Combined') {
                    # Add identifiers to command string
                    $CmdParam = @{
                        $Detailed = (Invoke-Endpoint @Param).resources
                    }
                    # Re-run command for identifier detail
                    & $Command @CmdParam
                } else {
                    # Output result
                    Invoke-Endpoint @Param
                }
            }
        }
    }
}