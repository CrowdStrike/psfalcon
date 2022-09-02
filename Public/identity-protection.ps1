function Invoke-FalconIdentityGraph {
<#
.SYNOPSIS
Interact with Falcon Identity using GraphQL
.DESCRIPTION
Requires 'Identity Protection GraphQL: Write'.
.PARAMETER Query
A complete GraphQL query statement
.PARAMETER All
Repeat requests until all available results are retrieved
#>
    [CmdletBinding(DefaultParameterSetName='/identity-protection/combined/graphql/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/identity-protection/combined/graphql/v1:post',Mandatory,ValueFromPipeline,
            Position=1)]
        [string]$Query,
        [Parameter(ParameterSetName='/identity-protection/combined/graphql/v1:post')]
        [switch]$All
    )
    begin {
        function Invoke-GraphLoop ($Object,$Splat,$Inputs) {
            if ($Inputs.Query -notmatch 'pageInfo(\s+)?{(\s+)?(hasNextPage(\s+)?|endCursor(\s+)?){2}(\s+)?}') {
                [string]$Message = "'-All' parameter was specified but 'pageInfo' is missing from query."
                Write-Warning ("[$($Splat.Command)]",$Message -join ' ')
            } else {
                do {
                    # Ensure 'after' is present with current endCursor value
                    [string]$After = 'after:"{0}"' -f $Object.entities.pageInfo.endCursor
                    [string]$Entities = [regex]::Match($Inputs.Query,'entities(\s+)?\([\w\s:\[\],="]+[^)]').Value
                    [string]$Next = if ($Entities -match 'after:"[\w=]+"') {
                        $Entities -replace 'after:"[\w=]+"',$After
                    } else {
                        $Entities,$After -join ' '
                    }
                    # Update 'query' and repeat request
                    $Inputs['Query'] = ($Inputs.Query).Replace($Entities,$Next)
                    Write-GraphResult (Invoke-Falcon @Splat -Inputs $Inputs -OutVariable Object)
                } while (
                    $Object.entities.pageInfo.hasNextPage -eq $true -and $null -ne
                        $Object.entities.pageInfo.endCursor
                )
            }
        }
        function Write-GraphResult ($Object) {
            if ($Object.entities.pageInfo) {
                # Output verbose 'pageInfo' detail
                [string]$Message = (@($Object.entities.pageInfo.PSObject.Properties).foreach{
                    $_.Name,$_.Value -join '='
                }) -join ', '
                Write-Verbose ('[Invoke-FalconIdentityGraph]',$Message -join ' ')
            }
            # Output 'nodes'
            if ($Object.entities.nodes) { $Object.entities.nodes } else { $Object }
        }
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/identity-protection/combined/graphql/v1:post'
            Format = @{ Body = @{ root = @('query') }}
        }
    }
    process {
        switch ($PSBoundParameters.Query) {
            { $_ -match '\n' } {
                if ($PSBoundParameters.Query -match '\#(\s+)?(\w|\W|\s).+') {
                    # Remove comments
                    $PSBoundParameters.Query = $PSBoundParameters.Query -replace '\#(\s+)?(\w|\W|\s).+',$null
                }
                # Convert into a single line and remove duplicate spaces
                $PSBoundParameters.Query = $PSBoundParameters.Query -replace '\n',' ' -replace '\s+',' '
            }
            # Enforce beginning and ending braces
            { $_ -notmatch '^{' } { $PSBoundParameters.Query = "{$($PSBoundParameters.Query)" }
            { $_ -notmatch '}$' } { $PSBoundParameters.Query = "$($PSBoundParameters.Query)}" }
            { $_ -match '}$' } {
                # Verify that the number of open braces matches the number of close braces
                [int]$Open = ($PSBoundParameters.Query.GetEnumerator() | Where-Object { $_ -eq '{' }).Count
                [int]$Close = ($PSBoundParameters.Query.GetEnumerator() | Where-Object { $_ -eq '}' }).Count
                [int]$Diff = $Open - $Close
                [string[]]$Append = if ($Diff -ge 1) { @(1..$Diff).foreach{ '}' } }
                if ($Append) { $PSBoundParameters.Query += $Append -join $null }
            }
        }
        if ($PSBoundParameters.All) {
            # Output relevant sub-objects and repeat requests when using 'All'
            Write-GraphResult (Invoke-Falcon @Param -Inputs $PSBoundParameters -OutVariable Request)
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end { if ($PSBoundParameters.All -and $Request) { Invoke-GraphLoop $Request $Param $PSBoundParameters }}
}