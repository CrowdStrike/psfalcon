function Disable-HumioEventCollector {
<#
.SYNOPSIS
Disable PSFalcon logging to Humio
.DESCRIPTION
Disables the sending of PSFalcon events to Humio. To completely remove a previously configured Humio destination,
use 'Remove-HumioEventCollector'.
#>
    [CmdletBinding()]
    param()
    process {
        if ($Script:Humio:Path -and $Script:Humio.Token) {
            $Script:Humio.Enabled = $false
            Write-Verbose "[Disable-HumioEventCollector] Disabled '$($Script:Humio.Path)'."
        } else {
            Write-Error "Humio destination has not been defined. Try 'Register-HumioEventCollector'."
        }
    }
}
function Enable-HumioEventCollector {
<#
.SYNOPSIS
Enable PSFalcon logging to Humio
.DESCRIPTION
Enables the sending of PSFalcon events to Humio using the destination defined with 'Register-HumioEventCollector'.
#>
    [CmdletBinding()]
    param()
    process {
        if ($Script:Humio:Path -and $Script:Humio.Token) {
            $Script:Humio.Enabled = $true
            Write-Verbose "[Enable-HumioEventCollector] Enabled '$($Script:Humio.Path)'."
        } else {
            Write-Error "Humio destination has not been defined. Try 'Register-HumioEventCollector'."
        }
    }
}
function Register-HumioEventCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [Alias('humio_path')]
        [System.Uri] $Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Alias('humio_token')]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Token
    )
    process {
        $Script:Humio = @{
            Path    = $PSBoundParameters.Path
            Token   = $PSBoundParameters.Token
            Enabled = $false
        }
        if ($Script:Falcon -and -not $Script:Falcon.Request) {
            $Script:Falcon['Request'] = @{}
        }
        Write-Verbose "[Register-HumioEventCollector] Added destination '$($Script:Humio.Path)'."
    }
}
function Remove-HumioEventCollector {
    [CmdletBinding()]
    param()
    process {
        if (Get-Variable -Name Humio -Scope Script -ErrorAction SilentlyContinue) {
            Remove-Variable -Name Humio -Scope Script
            Write-Verbose "[Remove-HumioEventCollector] Removed destination '$($Script:Humio.Path)'."
        }
    }
}
function Show-HumioEventCollector {
    [CmdletBinding()]
    param()
    process {
        [PSCustomObject] @{
            Path  = if ($Script:Humio.Path) {
                $Script:Humio.Path
            } else {
                $null
            }
            Token = if ($Script:Humio.Token) {
                $Script:Humio.Token
            } else {
                $null
            }
            Enabled = if ($Script:Humio.Enabled) {
                $Script:Humio.Enabled
            } else {
                $false
            }
        }
    }
}