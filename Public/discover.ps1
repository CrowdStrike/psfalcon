function Get-FalconAsset {
<#
.SYNOPSIS
Search for assets in Falcon Discover
.DESCRIPTION
Requires 'Falcon Discover: Read'.
.PARAMETER Id
Asset identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Include
Include additional properties
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.PARAMETER Account
Search for user account assets
.PARAMETER Login
Search for login events
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Discover
#>
    [CmdletBinding(DefaultParameterSetName='/discover/queries/hosts/v1:get')]
    param(
        [Parameter(ParameterSetName='/discover/entities/hosts/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/discover/entities/accounts/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/discover/entities/logins/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}_\w+$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=1)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=1)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=2)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=2)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=3)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=3)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=3)]
        [ValidateRange(1,100)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=4)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=4)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=4)]
        [int32]$Offset,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=5)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=5)]
        [ValidateSet('login_event',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [switch]$Total,
        [Parameter(ParameterSetName='/discover/entities/accounts/v1:get',Mandatory)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Mandatory)]
        [switch]$Account,
        [Parameter(ParameterSetName='/discover/entities/logins/v1:get',Mandatory)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Mandatory)]
        [switch]$Login
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('filter','sort','limit','offset','ids') }
            Max = 100
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        $Request = if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } elseif ($Detailed -and ($Login -or $Account)) {
            [void]$PSBoundParameters.Remove('Detailed')
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
            if ($Request -and $Account) {
                & $MyInvocation.MyCommand.Name -Id $Request -Account
            } elseif ($Request -and $Login) {
                & $MyInvocation.MyCommand.Name -Id $Request -Login
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
        if ($Request -and $PSBoundParameters.Include) {
            if (!$Request.id) {
                $Request = if ($PSBoundParameters.Account) {
                    # Create objects using 'id' values
                    @($Request).foreach{ ,[PSCustomObject]@{ id = $_ }}
                } else {
                    # Request detailed results for regular assets
                    & $MyInvocation.MyCommand.Name -Id $Request
                }
            }
            if ($PSBoundParameters.Include -contains 'login_event') {
                # Define property to match 'login' results with 'id' value
                [string]$Property = if ($PSBoundParameters.Account) { 'account_id' } else { 'host_id' }
                [int]$Count = if ($PSBoundParameters.Account) {
                    ($Request | Measure-Object).Count
                } else {
                    # Retrict to 'managed' assets as others won't have login events
                    ($Request | Where-Object { $_.entity_type -eq 'managed' }).Count
                }
                for ($i = 0; $i -lt $Count; $i += 20) {
                    # In groups of 20, perform filtered search for login events
                    [object[]]$Match = if ($PSBoundParameters.Account) {
                        @($Request)[$i..($i + 19)]
                    } else {
                        @($Request | Where-Object { $_.entity_type -eq 'managed' })[$i..($i + 19)]
                    }
                    [string]$Filter = @($Match[$i..($i + 19)]).foreach{ "$($Property):'$($_.id)'" } -join ','
                    foreach ($Item in (& $MyInvocation.MyCommand.Name -Filter $Filter -Detailed -Login -EA 0)) {
                        # Append matched login events to 'id' using 'host_id' or 'account_id'
                        foreach ($r in $Match) {
                            $AddParam = @{
                                Object = $Request | Where-Object { $_.id -eq $r.id }
                                Name = 'login_event'
                                Value = $Item | Where-Object { $_.$Property -eq $r.id }
                            }
                            Set-Property @AddParam
                        }
                    }
                }
            }
        }
        $Request
    }
}