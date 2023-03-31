#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS

.PARAMETER

#>
param(
    [Parameter(Mandatory,Position=1)]
    [ValidateSet('https://api.crowdstrike.com','https://api.us-2.crowdstrike.com',
        'https://api.laggar.gcw.crowdstrike.com','https://api.eu-1.crowdstrike.com')]
    [string]$BaseAddress,
    [Parameter(Mandatory,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ClientId,
    [Parameter(Mandatory,Position=3)]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,
    [Parameter(Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$MemberCid,
    [Parameter(Mandatory,Position=5)]
    [ValidatePattern('\.csv$')]
    [ValidateScript({ Test-Path $_ })]
    [string]$Path
)
$Param = @{
    Hostname = $BaseAddress
    ClientId = $ClientId
    ClientSecret = $ClientSecret
}
if ($MemberCid) { $Param['MemberCid'] = $MemberCid }
Request-FalconToken @Param
if ((Test-FalconToken).Token -eq $true) {
    $CSV = Import-Csv $Path
    @($CSV).foreach{
        @($_.PSObject.Properties.Name).foreach{
            if ($_ -notmatch '^(Email|Firstname|Lastname|Roles)$') {
                # Error if invalid columns exist
                throw "Unexpected column. Ensure 'Email', 'Firstname', 'Lastname' and 'Roles' are present. ['$_']"
            }
        }
        if ($_.Roles) {
            # Convert Roles into an [array]
            $_.Roles = ($_.Roles -Split ',').Trim()
        }
    }
    if ($CSV.Roles -and $CSV.Roles -match '\s') {
        # Replace 'Display Names' (from console output) with role IDs
        $Roles = Get-FalconRole -Detailed
        if ($Roles) {
            @($CSV).foreach{
                $_.Roles = @($_.Roles).foreach{
                    $_ -replace $_,($Roles | Where-Object display_name -eq $_).id
                }
            }
        }
    }
    $CSV | ForEach-Object {
        # Create user
        $User = New-FalconUser -Username $_.Email -Firstname $_.Firstname -Lastname $_.Lastname
        if ($User.uuid -and $_.Roles) {
            # Assign roles
            Add-FalconRole -UserId $User.uuid -Id $_.Roles
        } elseif ($User.uuid) {
            # Assign 'falcon_console_guest' if roles are not present
            Add-FalconRole -UserId $User.uuid -Id falcon_console_guest
        }
    }
}