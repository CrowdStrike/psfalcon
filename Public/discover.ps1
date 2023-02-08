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
.PARAMETER Application
Search for applications
.PARAMETER Login
Search for login events
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconAsset
#>
    [CmdletBinding(DefaultParameterSetName='/discover/queries/hosts/v1:get',SupportsShouldProcess)]
    [OutputType('PSFalcon.domain.DiscoverAPIAccount',ParameterSetName='/discover/entities/accounts/v1:get')]
    [OutputType('PSFalcon.domain.DiscoverAPIApplication',
        ParameterSetName='/discover/entities/applications/v1:get')]
    [OutputType('PSFalcon.domain.DiscoverAPIHost',ParameterSetName='/discover/entities/hosts/v1:get')]
    [OutputType('PSFalcon.domain.DiscoverAPILogin',ParameterSetName='/discover/entities/logins/v1:get')]
    [OutputType([string],ParameterSetName='/discover/queries/accounts/v1:get')]
    [OutputType([string],ParameterSetName='/discover/queries/applications/v1:get')]
    [OutputType([string],ParameterSetName='/discover/queries/hosts/v1:get')]
    [OutputType([string],ParameterSetName='/discover/queries/logins/v1:get')]
    param(
        [Parameter(ParameterSetName='/discover/entities/hosts/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [Parameter(ParameterSetName='/discover/entities/accounts/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [Parameter(ParameterSetName='/discover/entities/applications/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [Parameter(ParameterSetName='/discover/entities/logins/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}_\w+$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=1)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=1)]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Position=1)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=2)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=2)]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Position=2)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=2)]
        [string]$Sort,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=3)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=3)]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Position=3)]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get',Position=3)]
        [ValidateRange(1,100)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get',Position=4)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Position=4)]
        [ValidateSet('login_event',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/discover/queries/hosts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get')]
        [Parameter(ParameterSetName='/discover/queries/logins/v1:get')]
        [switch]$Total,
        [Parameter(ParameterSetName='/discover/entities/accounts/v1:get',Mandatory)]
        [Parameter(ParameterSetName='/discover/queries/accounts/v1:get',Mandatory)]
        [switch]$Account,
        [Parameter(ParameterSetName='/discover/entities/applications/v1:get',Mandatory)]
        [Parameter(ParameterSetName='/discover/queries/applications/v1:get',Mandatory)]
        [switch]$Application,
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
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/discover/entities/accounts/v1:get' { 'domain.DiscoverAPIAccount' }
                '/discover/entities/applications/v1:get' { 'domain.DiscoverAPIApplication' }
                '/discover/entities/hosts/v1:get' { 'domain.DiscoverAPIHost' }
                '/discover/entities/logins/v1:get' { 'domain.DiscoverAPILogin' }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        $Request = if ($Detailed -and ($Login -or $Account -or $Application)) {
            [void]$PSBoundParameters.Remove('Detailed')
            $IdList = Invoke-Falcon @Param -Inputs $PSBoundParameters
            if ($IdList -and $Account) {
                $IdList | & $MyInvocation.MyCommand.Name -Account
            } elseif ($IdList -and $Application) {
                $IdList | & $MyInvocation.MyCommand.Name -Application
            } elseif ($IdList -and $Login) {
                $IdList | & $MyInvocation.MyCommand.Name -Login
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
        if ($Include) {
            if (!$Request.id) { $Request = @($Request).foreach{ ,[PSCustomObject]@{ id = $_ }}}
            if ($Include -contains 'login_event') {
                # Define property to match 'login' results with 'id' value
                [string]$Property = if ($Account) { 'account_id' } else { 'host_id' }
                for ($i = 0; $i -lt ($Request | Measure-Object).Count; $i += 100) {
                    # In groups of 100, perform filtered search for login events
                    $Group = $Request[$i..($i + 99)]
                    $Filter = @($Group.id).foreach{ $Property,"'$_'" -join ':' } -join ','
                    $Content = & $MyInvocation.MyCommand.Name -Filter $Filter -Detailed -All -Login -EA 0
                    foreach ($Value in @($Content.$Property | Select-Object -Unique)) {
                        @($Group).Where({ $_.id -eq $Value }).foreach{
                            # Append matched login events to 'id' using 'host_id' or 'account_id'
                            Set-Property $_ login_event @($Content).Where({ $_.$Property -eq $Value })
                        }
                    }
                }
            }
        }
        $Request
    }
}