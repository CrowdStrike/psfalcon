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
.PARAMETER Include
Include additional properties
.PARAMETER Offset
Position to begin retrieving results
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
    [CmdletBinding(DefaultParameterSetName='/discover/queries/hosts/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/discover/entities/hosts/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/discover/entities/accounts/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName='/discover/entities/logins/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-fA-F0-9]{32}_\w+$')]
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
        [ValidateSet('login_event',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [int32]$Offset,
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
        if ($Request -and $Include) {
            if (!$Request.id) { $Request = @($Request).foreach{ ,[PSCustomObject]@{ id = $_ }}}
            if ($Include -contains 'login_event') {
                # Define property to match 'login' results with 'id' value
                [string]$p = if ($Account) { 'account_id' } else { 'host_id' }
                [int]$Count = ($Request | Measure-Object).Count
                for ($i = 0; $i -lt $Count; $i += 20) {
                    # In groups of 20, perform filtered search for login events
                    [object[]]$Group = @($Request)[$i..($i + 19)]
                    [string]$Filter = @($Group[$i..($i + 19)]).foreach{ "$($p):'$($_.id)'" } -join ','
                    foreach ($e in (& $MyInvocation.MyCommand.Name -Filter $Filter -Detailed -Login -EA 0)) {
                        # Append matched login events to 'id' using 'host_id' or 'account_id'
                        foreach ($a in $Group) {
                            $SetParam = @{
                                Object = $Request | Where-Object { $_.id -eq $a.id }
                                Name = 'login_event'
                                Value = @($e | Where-Object { $_.$p -eq $a.id })
                            }
                            Set-Property @SetParam
                        }
                    }
                }
            }
        }
        $Request
    }
}