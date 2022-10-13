function Invoke-FalconIdentityGraph {
<#
.SYNOPSIS
Interact with Falcon Identity using GraphQL
.DESCRIPTION
Requires 'Identity Protection GraphQL: Write'.
.PARAMETER Query
A complete GraphQL query statement
.PARAMETER Mutation
A complete GraphQL mutation statement
.PARAMETER Variable
A hashtable containing variables used in your GraphQL query statement
.PARAMETER All
Repeat requests until all available results are retrieved
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconIdentityGraph
#>
    [CmdletBinding(DefaultParameterSetName='Query',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='Query',Mandatory,ValueFromPipeline,Position=1)]
        [string]$Query,
        [Parameter(ParameterSetName='Mutation',Mandatory,ValueFromPipeline,Position=1)]
        [string]$Mutation,
        [Parameter(ParameterSetName='Query',ValueFromPipeline,Position=2)]
        [Alias('variables')]
        [hashtable]$Variable,
        [Parameter(ParameterSetName='Query')]
        [switch]$All
    )
    begin {
        function Test-Statement ($String) {
            function Get-CharacterCount ($String,$Character) {
                # Count the number of character occurances within a string
                ($String.GetEnumerator() | Where-Object { $_ -eq $Character }).Count
            }
            if ($String -and $String -notmatch '^(\s+)?mutation') {
                [string]$Comment = '\#(\s+)?(\w|\W|\s).+'
                switch ($String) {
                    { $_ -match '\n' } {
                        # Remove comments, convert to single line and remove duplicate spaces
                        if ($String -match $Comment) { $String = $String -replace $Comment,$null }
                        $String = $String -replace '\n',' ' -replace '\s+',' '
                    }
                    # Enforce beginning and ending braces
                    { $_ -notmatch '^(\s+)?{' } { $String = "{$($String)" }
                    { $_ -notmatch '}(\s+)?$' } { $String = "$($String)}" }
                    { $_ -match '(^(\s+)?{|}(\s+)?$)' } {
                        # Verify that the number of braces match
                        [int]$Open = Get-CharacterCount $String '{'
                        [int]$Close = Get-CharacterCount $String '}'
                        if ($Open -ne $Close) {
                            if (($Close - $Open) -ge 1) {
                                do {
                                    # Append opening braces
                                    $String = ((@(1..($Close - $Open)).foreach{ '{' }) -join $null),
                                        $String -join $null
                                    [int]$Open = Get-CharacterCount $String '{'
                                } until ( ($Close - $Open) -le 0 )
                            }
                            if (($Open - $Close) -ge 1) {
                                do {
                                    # Append closing braces
                                    $String += (@(1..($Open - $Close)).foreach{ '}' }) -join $null
                                    [int]$Close = Get-CharacterCount $String '}'
                                } until ( ($Open - $Close) -le 0 )
                            }
                        }
                    }
                }
            }
            $String
        }
        function Invoke-GraphLoop ($Object,$Splat,$Inputs) {
            [string]$PageInfo = 'pageInfo(\s+)?{(\s+)?(hasNextPage([,\s]+)?|endCursor([,\s]+)?){2}(\s+)?}'
            if ($Inputs.Query -notmatch $PageInfo) {
                [string]$Message = "'-All' parameter was specified but 'pageInfo' is missing from query."
                Write-Warning ("[$($Splat.Command)]",$Message -join ' ')
            } else {
                do {
                    if ($Inputs.Query -notmatch '\$after') {
                        # Ensure 'after' is present with current endCursor value in query statement
                        [string]$After = 'after:"{0}"' -f $Object.entities.pageInfo.endCursor
                        [string]$Entities = [regex]::Match($Inputs.Query,
                            'entities(\s+)?\([.$\w\s:\[\],="]+[^)]').Value
                        [string]$Next = if ($Entities -match 'after:"[\w=]+"') {
                            $Entities -replace 'after:"[\w=]+"',$After
                        } else {
                            $Entities,$After -join ' '
                        }
                        $Inputs['Query'] = ($Inputs.Query).Replace($Entities,$Next)
                    } elseif ($Inputs.Variables -and $Inputs.Variables.ContainsKey('After')) {
                        # Update 'after' variable
                        $Inputs.Variables.After = $Object.entities.pageInfo.endCursor
                    } else {
                        # Add 'variables' with current 'after' endCursor value
                        $Inputs['Variable'] = @{ after = $Object.entities.pageInfo.endCursor }
                    }
                    # Repeat request
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
        <#
        $RegEx = @{
            # RegEx patterns for query modification
            AfterDef = '^(\s+)?(query)?(\s+)?\((\s+)?\$after(\s+)?:(\s+)?cursor(\s+)?\)(\s+)?{'
            AfterVar = 'after(\s+)?:(\s+)?\$after'
            Comment = '\#(\s+)?(\w|\W|\s).+'
            Prefix = '^(\s+)?query(\s+)?'
        }
        #>
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/identity-protection/combined/graphql/v1:post'
            Format = @{ Body = @{ root = @('query','variables') }}
        }
    }
    process {
        if ($PSBoundParameters.Query) {
            <#
            switch ($PSBoundParameters.Query) {
                { $_ -match $RegEx.Prefix } {
                    # Remove 'query' prefix
                    $PSBoundParameters.Query = $PSBoundParameters.Query -replace $RegEx.Prefix,$null
                }
                { $_ -match $RegEx.AfterDef } {
                    # Remove prefix 'after' variable definition and closing brace
                    $PSBoundParameters.Query = $PSBoundParameters.Query -replace $RegEx.AfterDef,$null
                }
                { $_ -match $RegEx.AfterVar } {
                    # Remove 'after' when using variable and add 'All'
                    $PSBoundParameters.Query = $PSBoundParameters.Query -replace $RegEx.AfterVar,$null
                    if (!$PSBoundParameters.All) { $PSBoundParameters['All'] = $true }
                }
            }
            #>
            $PSBoundParameters.Query = Test-Statement $PSBoundParameters.Query
        }
        if ($PSBoundParameters.Mutation) {
            # Submit 'Mutation' as 'Query'
            $PSBoundParameters['Query'] = $PSBoundParameters.Mutation
            [void]$PSBoundParameters.Remove('Mutation')
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
