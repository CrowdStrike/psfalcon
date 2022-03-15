function Export-FalconReport {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [ValidatePattern('\.csv$')]
        [string] $Path,

        [Parameter(Mandatory = $true, ValueFromPipeLine = $true, Position = 2)]
        [object] $Object
    )
    begin {
        function Get-Array ($Array, $Output, $Name) {
            foreach ($Item in $Array) {
                if ($Item.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
                    # Add sub-objects to output
                    $IdField = $Item.PSObject.Properties.Name -match '^(id|(device|policy)_id)$'
                    if ($IdField) {
                        $ObjectParam = @{
                            Object = $Item | Select-Object -ExcludeProperty $IdField
                            Output = $Output
                            Prefix = "$($Name).$($Item.$IdField)"
                        }
                        Get-PSObject @ObjectParam
                    } else {
                        $ObjectParam = @{
                            Object = $Item
                            Output = $Output
                            Prefix = $Name
                        }
                        Get-PSObject @ObjectParam
                    }
                } else {
                    # Add property to output as 'name'
                    $AddParam = @{
                        Object = $Output
                        Name   = $Name
                        Value  = $Array -join ','
                    }
                    Add-Property @AddParam
                }
            }
        }
        function Get-PSObject ($Object, $Output, $Prefix) {
            foreach ($Item in ($Object.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })) {
                if ($Item.Value.PSObject.TypeNames -contains 'System.Object[]') {
                    # Add array members to output with 'prefix.name'
                    $ArrayParam = @{
                        Array  = $Item.Value
                        Output = $Output
                        Name   = if ($Prefix) { "$($Prefix).$($Item.Name)" } else { $Item.Name }
                    }
                    Get-Array @ArrayParam
                } elseif ($Item.Value.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
                    # Add sub-objects to output with 'prefix.name'
                    $ObjectParam = @{
                        Object = $Item.Value
                        Output = $Output
                        Prefix = if ($Prefix) { "$($Prefix).$($Item.Name)" } else { $Item.Name }
                    }
                    Get-PSObject @ObjectParam
                } else {
                    # Add property to output with 'prefix.name'
                    $AddParam = @{
                        Object = $Output
                        Name   = if ($Prefix) { "$($Prefix).$($Item.Name)" } else { $Item.Name }
                        Value  = $Item.Value
                    }
                    Add-Property @AddParam
                }
            }
        }
        $Output = [PSCustomObject] @{}
    }
    process {
        foreach ($Item in $PSBoundParameters.Object) {
            if ($Item.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
                # Add sorted properties to output
                Get-PSObject -Object $Item -Output $Output
            } else {
                # Add strings to output as 'id'
                $AddParam = @{
                    Object = $Output
                    Name   = 'id'
                    Value  = $Item
                }
                Add-Property @AddParam
            }
        }
        if ($PSBoundParameters.Path) {
            # Output to CSV
            $ExportParam = @{
                InputObject       = $Output
                Path              = $Script:Falcon.Api.Path($PSBoundParameters.Path)
                NoTypeInformation = $true
                Append            = $true
            }
            Export-Csv @ExportParam
        } else {
            # Output to console
            $Output
        }
    }
    end {
        if ($ExportParam -and (Test-Path $ExportParam.Path)) { Get-ChildItem $ExportParam.Path }
    }
}
function Send-FalconWebhook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('Slack')]
        [string] $Type,

        [Parameter(Mandatory = $true, Position = 2)]
        [System.Uri] $Path,

        [Parameter(Position = 3)]
        [string] $Label,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 4)]
        [object] $Object
    )
    begin {
        $Token = if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
            # Remove default Falcon authorization token
            $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization
            [void] $Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
        }
    }
    process {
        [array] $Content = switch ($PSBoundParameters.Type) {
            'Slack' {
                # Create 'attachment' for each object in submission
                @($Object | Export-FalconReport).foreach{
                    [array] $Fields = @($_.PSObject.Properties).foreach{
                        ,@{
                            title = $_.Name
                            value = if ($_.Value -is [boolean]) {
                                # Convert [boolean] to [string]
                                if ($_.Value -eq $true) { 'true' } else { 'false' }
                            } else {
                                # Add [string] value when $null
                                if ($null -eq $_.Value) { 'null' } else { $_.Value }
                            }
                            short = $false
                        }
                    }
                    ,@{
                        username    = "PSFalcon: $($Script:Falcon.ClientId)"
                        icon_url    = 'https://raw.githubusercontent.com/CrowdStrike/psfalcon/master/icon.png'
                        text        = $PSBoundParameters.Label
                        attachments = @(
                            @{
                                fallback = 'Send-FalconWebhook'
                                fields   = $Fields
                            }
                        )
                    }
                }
            }
        }
        foreach ($Item in $Content) {
            try {
                $Param = @{
                    Path    = $PSBoundParameters.Path
                    Method  = 'post'
                    Headers = @{ ContentType = 'application/json' }
                    Body = ConvertTo-Json -InputObject $Item -Depth 32
                }
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result -Request $Request
            } catch {
                throw $_
            }
        }
    }
    end {
        if ($Token -and !$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
            # Restore default Falcon authorization token
            $Script:Falcon.Api.Client.DefaultRequestHeaders.Add('Authorization', $Token)
        }
    }
}
function Show-FalconMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [array] $Indicators
    )
    begin {
        $FalconUI = "$($Script:Falcon.Hostname -replace 'api', 'falcon')"
        $Inputs = ($PSBoundParameters.Indicators).foreach{
            $Type = Test-RegexValue $_
            $Value = if ($Type -match '^(domain|md5|sha256)$') { $_.ToLower() } else { $_ }
            if ($Type) { "$($Type):'$Value'" }
        }
    }
    process {
        Start-Process "$($FalconUI)/intelligence/graph?indicators=$($Inputs -join ',')"
    }
}
function Show-FalconModule {
    [CmdletBinding()]
    param()
    process {
        $ManifestPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'PSFalcon.psd1'
        if (Test-Path $ManifestPath) {
            $ModuleData = Import-PowerShellDataFile -Path $ManifestPath
            [PSCustomObject] @{
                PSVersion      = "$($PSVersionTable.PSEdition) [$($PSVersionTable.PSVersion)]"
                ModuleVersion  = "v$($ModuleData.ModuleVersion) {$($ModuleData.GUID)}"
                ModulePath     = Split-Path -Path $ManifestPath -Parent
                UserModulePath = $env:PSModulePath
                UserHome       = $HOME
                UserAgent      = "crowdstrike-psfalcon/$($ModuleData.ModuleVersion)"
            }
        } else {
            throw "Unable to locate '$ManifestPath'"
        }
    }
}