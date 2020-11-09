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
        if ($Loop.resources -and (($Loop.resources.count -lt $Loop.meta.pagination.total) -or
            $Loop.meta.pagination.next_page)) {
            for ($i = $Loop.resources.count; (($i -lt $Loop.meta.pagination.total) -or
                ($Loop.meta.pagination.next_page)); $i += $Loop.resources.count) {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] $i of $($Loop.meta.pagination.total)"
                if ($Loop.meta.pagination.after) {
                    $Param['After'] = $Loop.meta.pagination.after
                }
                else {
                    $Param['Offset'] = if ($Loop.meta.pagination.next_page) {
                        $Loop.meta.pagination.offset
                    }
                    elseif ($Loop.meta.pagination.offset -match '^\d{1,}$') {
                        $i
                    }
                    else {
                        $Loop.meta.pagination.offset
                    }
                }
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
            }
        }
    }
}