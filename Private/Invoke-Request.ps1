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
                Param = Get-LoopParam -Dynamic $Dynamic
            }
            switch ($Detailed) {
                'Combined' {
                    $LoopParam.Param['Detailed'] = $true
                }
                default {
                    $LoopParam['Detailed'] = $Detailed
                }
            }
            if ($Modifier) {
                $LoopParam.Param[$Modifier] = $true
            }
            Invoke-Loop @LoopParam
        }
        else {
            $Endpoint = if (($Dynamic.values | Where-Object IsSet).Attributes.ParameterSetName -eq $Entity) {
                $Entity
            }
            else {
                $Query
            }
            foreach ($Param in (Get-Param -Endpoint $Endpoint -Dynamic $Dynamic)) {
                Format-Param -Param $Param
                $Request = Invoke-Endpoint @Param
                if ($Request -and $Detailed -and $Detailed -ne 'Combined') {
                    $DetailParam = @{
                        $Detailed = $Request
                    }
                    & $Command @DetailParam
                }
                else {
                    $Request
                }
            }
        }
    }
}