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
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [string] $Command,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [hashtable] $Param,

        [Parameter()]
        [string] $Detailed
    )
    process {
        # Request identifiers
        $Loop = & $Command @Param

        if ($Detailed) {
            # Add parameter to target identifiers to command string
            $DetailParam = @{
                $Detailed = $Loop.resources
            }
            # Output detail about identifiers
            & $Command @DetailParam
        } else {
            # Output identifiers
            $Loop
        }
        if ($Loop.resources -and (($Loop.resources.count -lt $Loop.meta.pagination.total) -or
        $Loop.meta.pagination.next_page)) {

            Write-Verbose ("[$($MyInvocation.MyCommand.Name)] $($Loop.meta.pagination.total) total results")

            # Repeat requests if result count is less than total results, or until 'next_page' disappears
            for ($i = $Loop.resources.count; (($i -lt $Loop.meta.pagination.total) -or
            ($Loop.meta.pagination.next_page)); $i += $Loop.resources.count) {

                # Update position based on pagination results
                if ($Loop.meta) {
                    if ($Loop.meta.pagination.after) {
                        # token-based after
                        $Param['After'] = $Loop.meta.pagination.after
                    } else {
                        $Param['Offset'] = if ($Loop.meta.pagination.next_page) {
                            # uoffset value when 'next_page' is present
                            $Loop.meta.pagination.offset
                        } elseif ($Loop.meta.pagination.offset -match '^\d{1,}$') {
                            # current count for integer-offset
                            $i
                        } else {
                            # token-based offset
                            $Loop.meta.pagination.offset
                        }
                    }
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] received $i of $($Loop.meta.pagination.total)"

                    # Request identifiers
                    $Loop = & $Command @Param

                    if ($Detailed) {
                        # Add parameter to target identifiers to command string
                        $DetailParam = @{
                            $Detailed = $Loop.resources
                        }
                        # Output detail about identifiers
                        & $Command @DetailParam
                    } else {
                        # Output identifiers
                        $Loop
                    }
                } else {
                    # Output error
                    $Loop
                    break
                }
            }
        }
    }
}