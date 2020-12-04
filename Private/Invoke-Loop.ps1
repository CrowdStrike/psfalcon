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
    begin {
        function Set-Paging ($Object, $Param, $Count) {
            if ($Object.after) {
                $Param['After'] = $Object.after
            }
            else {
                if ($Object.next_page) {
                    $Param['Offset'] = $Object.offset
                }
                else {
                    $Param['Offset'] = if ($Object.offset -match '^\d{1,}$') {
                        $Count
                    }
                    else {
                        $Object.offset
                    }
                }
            }
        }
    }
    process {
        $Loop = @{
            Request = & $Command @Param
            Pagination = $Meta.pagination
        }
        if ($Loop.Request -and $Detailed -and ($Detailed -ne 'Combined')) {
            $DetailParam = @{
                $Detailed = $Loop.Request
            }
            & $Command @DetailParam
        }
        else {
            $Loop.Request
        }
        if ($Loop.Request -and (($Loop.Request.count -lt $Loop.Pagination.total) -or $Loop.Pagination.next_page)) {
            for ($i = $Loop.Request.count; ($Loop.Pagination.next_page -or ($i -lt $Loop.Pagination.total));
            $i += $Loop.Request.count) {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] retrieved $i results"
                Set-Paging -Object $Loop.Pagination -Param $Param -Count $i
                $Loop = @{
                    Request = & $Command @Param
                    Pagination = $Meta.pagination
                }
                if ($Loop.Request -and $Detailed -and ($Detailed -ne 'Combined')) {
                    $DetailParam = @{
                        $Detailed = $Loop.Request
                    }
                    & $Command @DetailParam
                }
                else {
                    $Loop.Request
                }
            }
        }
    }
}