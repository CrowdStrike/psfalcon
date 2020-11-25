function Invoke-Loop {
    <#
    .SYNOPSIS
        Watches 'meta' results and repeats commands
    .PARAMETER COMMAND
        The PSFalcon command to repeat
    .PARAMETER PARAM
        Parameters to include when running the command
    .PARAMETER DETAILED
        Toggle to perform a second request for detailed information about identifiers
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Command,

        [Parameter(Mandatory = $true)]
        [hashtable] $Param,

        [Parameter()]
        [string] $Detailed
    )
    process {
        $Loop = & $Command @Param
        if ($Loop.resources -and $Detailed -and $Detailed -ne 'Combined') {
            $DetailParam = @{
                $Detailed = $Loop.resources
            }
            & $Command @DetailParam
        }
        else {
            $Loop
        }
        if ($Loop -and (($Loop.count -lt $Meta.pagination.total) -or
        $Meta.pagination.next_page)) {
            for ($i = $Loop.count; (($i -lt $Meta.pagination.total) -or
                ($Meta.pagination.next_page)); $i += $Loop.count) {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] $i of $($Meta.pagination.total)"
                if ($Meta.pagination.after) {
                    $Param['After'] = $Meta.pagination.after
                }
                else {
                    $Param['Offset'] = if ($Meta.pagination.next_page) {
                        $Meta.pagination.offset
                    }
                    elseif ($Meta.pagination.offset -match '^\d{1,}$') {
                        $i
                    }
                    else {
                        $Meta.pagination.offset
                    }
                }
                $Loop = & $Command @Param
                if ($Loop -and $Detailed -and $Detailed -ne 'Combined') {
                    $DetailParam = @{
                        $Detailed = $Loop
                    }
                    & $Command @DetailParam
                }
                else {
                    $Loop
                }
            }
            if ($Script:Meta) {
                Remove-Variable -Name Meta -Scope Script
            }
        }
    }
}