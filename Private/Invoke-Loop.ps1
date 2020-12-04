function Invoke-Loop {
    <#
    .SYNOPSIS
        Watches 'meta' results and repeats commands
    .PARAMETER COMMAND
        The psfalcon command to repeat
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
        @('total', 'after', 'offset', 'next_page').foreach{
            if ($Meta.pagination.$_) {
                Set-Variable -Name $_ -Value $Meta.pagination.$_
            }
        }
        if ($Loop -and $Detailed -and ($Detailed -ne 'Combined')) {
            $DetailParam = @{
                $Detailed = $Loop
            }
            & $Command @DetailParam
        }
        else {
            $Loop
        }
        if ($Loop -and (($Loop.count -lt $total) -or $next_page)) {
            for ($i = $Loop.count; ($next_page -or ($i -lt $total)); $i += $Loop.count) {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] retrieved $i results"
                if ($after) {
                    $Param['After'] = $after
                }
                elseif ($offset) {
                    $Param['Offset'] = if ($next_page) {
                        $offset
                    }
                    elseif ($offset -match '^\d{1,}$') {
                        $i
                    }
                    else {
                        $offset
                    }
                }
                $Loop = & $Command @Param
                @('total', 'after', 'offset', 'next_page').foreach{
                    if ($Meta.pagination.$_) {
                        Set-Variable -Name $_ -Value $Meta.pagination.$_
                    }
                }
                if ($Loop -and $Detailed -and ($Detailed -ne 'Combined')) {
                    $DetailParam = @{
                        $Detailed = $Loop
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