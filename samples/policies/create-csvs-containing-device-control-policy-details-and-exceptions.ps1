#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Create a CSV containing Device Control policy info (settings, members, groups, exceptions) using id or name
.PARAMETER ClientId
OAuth2 client identifier
.PARAMETER ClientSecret
OAuth2 client secret
.PARAMETER Cloud
CrowdStrike cloud [default: 'us-1']
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Path
Target directory for CSV output
#>
[CmdletBinding(DefaultParameterSetName='Id')]
param(
    [Parameter(ParameterSetName='Id',Mandatory,Position=1)]
    [Parameter(ParameterSetName='Name',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ClientId,
    [Parameter(ParameterSetName='Id',Mandatory,Position=2)]
    [Parameter(ParameterSetName='Name',Mandatory,Position=2)]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,
    [Parameter(ParameterSetName='Id',Position=3)]
    [Parameter(ParameterSetName='Name',Position=3)]
    [ValidateSet('eu-1','us-gov-1','us-1','us-2')]
    [string]$Cloud,
    [Parameter(ParameterSetName='Id',Mandatory,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='Name',Mandatory,Position=5)]
    [string]$Name,
    [Parameter(ParameterSetName='Id',Position=6)]
    [Parameter(ParameterSetName='Name',Position=6)]
    [ValidateScript({
        if ((Test-Path $_) -eq $false) {
            throw "Cannot find path '$_' because it does not exist."
        } elseif ((Test-Path $_ -PathType Container) -eq $false) {
            throw "'Path' must specify a directory."
        } else {
            $true
        }
    })]
    [string]$Path
)
begin {
    function Write-CsvOutput ([object]$Content,[string]$Type) {
        if ($Content) {
            $Param = @{
                Path = Join-Path $OutputFolder "$((Get-Date -Format FileDate),$PolicyId,$Type -join '_').csv"
                NoTypeInformation = $true
                Append = $true
                Force = $true
            }
            $Content | Export-Csv @Param
        }
    }
    [string]$OutputFolder = if (!$Path) { (Get-Location).Path } else { $Path }
    $Token = @{ ClientId = $ClientId; ClientSecret = $ClientSecret }
    if ($Cloud) { $Token['Cloud'] = $Cloud }
    Request-FalconToken @Token
    $VerbosePreference = 'Continue'
}
process {
    [string]$PolicyId = if ((Test-FalconToken).Token -eq $true) {
        if ($Name) {
            try {
                Get-FalconDeviceControlPolicy -Filter "name:'$($Name.ToLower())'"
            } catch {
                throw "No Device Control policy found matching '$($Name.ToLower())'."
            }
        } else {
            $Id
        }
    }
    if ($PolicyId) {
        foreach ($Item in (Get-FalconDeviceControlPolicy -Id $PolicyId)) {
            $Item.settings.PSObject.Members.Where({ $_.MemberType -eq 'NoteProperty' }).foreach{
                if ($_.Name -eq 'classes') {
                    Write-CsvOutput ($_.Value | Select-Object id,action) 'classes'
                    foreach ($Exception in ($_.Value).Where({ $_.exceptions }).exceptions) {
                        Write-CsvOutput $Exception 'exceptions'
                    }
                } else {
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty($_.Name,$_.Value)))
                }
            }
            foreach ($Property in @('groups','settings')) {
                if ($Item.$Property -and $Property -eq 'groups') {
                    Write-CsvOutput ($Item.$Property | Select-Object id,name) $Property
                }
                $Item.PSObject.Properties.Remove($Property)
            }
            Write-CsvOutput $Item 'settings'
            Write-CsvOutput (Get-FalconDeviceControlPolicyMember -Id $PolicyId -Detailed -All |
                Select-Object device_id,hostname) 'members'
        }
    }
}
end { if (Test-Path $OutputFolder) { Get-ChildItem $OutputFolder | Select-Object FullName,Length,LastWriteTime }}