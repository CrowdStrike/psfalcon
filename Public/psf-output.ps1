function Export-FalconReport {
<#
.SYNOPSIS
Format a response object and output to console or CSV
.DESCRIPTION
If providing a string, values will be exported with a single 'id' column.

PSFalcon response objects will exported with available properties to ensure CSV compatibility. Use
'Select-Object' to pre-filter any unwanted properties.
.PARAMETER Path
Destination path
.PARAMETER Object
Response object
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Export-FalconReport
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [ValidatePattern('\.csv$')]
        [string]$Path,
        [Parameter(Mandatory,ValueFromPipeline,Position=2)]
        [object[]]$Object
    )
    begin {
        if ($Path) { $Path = $Script:Falcon.Api.Path($Path) }
        $OutPath = Test-OutFile $Path
        if ($OutPath.Category -eq 'WriteError' -and !$Force) { Write-Error @OutPath }
    }
    process {
        $Object | ForEach-Object {
            [string[]]$Select = $_.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames
            $Output = if ($Select) {
                $_ | Select-Object $Select
            } elseif ($_ -is [string]) {
                [PSCustomObject]@{ id = $_ }
            } else {
                $_
            }
            if ($Path -and !$OutPath) {
                $Output | Export-Csv $Path -NoTypeInformation -Append
            } elseif (!$Path) {
                $Output
            }
        }
    }
    end {
        if ($Path -and (Test-Path $Path) -and !$OutPath) {
            Get-ChildItem $Path | Select-Object FullName,Length,LastWriteTime
        }
    }
}
function Send-FalconWebhook {
<#
.SYNOPSIS
Send a PSFalcon object to a supported Webhook
.DESCRIPTION
Sends an object to a Webhook, converting the object to an acceptable format when required
.PARAMETER Type
Webhook type
.PARAMETER Path
Webhook URL
.PARAMETER Label
Message label
.PARAMETER Object
Response object to format
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconWebhook
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=1)]
        [ValidateSet('Slack')]
        [string]$Type,
        [Parameter(Mandatory,Position=2)]
        [System.Uri]$Path,
        [Parameter(Position=3)]
        [string]$Label,
        [Parameter(Mandatory,ValueFromPipeline,Position=4)]
        [object]$Object
    )
    begin {
        $Token = if ($Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
            # Remove default Falcon authorization token
            $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization
            [void]$Script:Falcon.Api.Client.DefaultRequestHeaders.Remove('Authorization')
        }
    }
    process {
        [object[]]$Content = switch ($PSBoundParameters.Type) {
            'Slack' {
                # Create 'attachment' for each object in submission
                @($Object | Export-FalconReport).foreach{
                    [object[]]$Fields = @($_.PSObject.Properties).foreach{
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
                        username = 'PSFalcon',$Script:Falcon.ClientId -join ': '
                        icon_url = 'https://raw.githubusercontent.com/CrowdStrike/psfalcon/master/icon.png'
                        text = $PSBoundParameters.Label
                        attachments = @(
                            @{
                                fallback = 'Send-FalconWebhook'
                                fields = $Fields
                            }
                        )
                    }
                }
            }
        }
        foreach ($Item in $Content) {
            try {
                $Param = @{
                    Path = $PSBoundParameters.Path
                    Method = 'post'
                    Headers = @{ ContentType = 'application/json' }
                    Body = ConvertTo-Json $Item -Depth 32
                }
                $Request = $Script:Falcon.Api.Invoke($Param)
                Write-Result $Request
            } catch {
                throw $_
            }
        }
    }
    end {
        if ($Token -and !$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization) {
            # Restore default Falcon authorization token
            $Script:Falcon.Api.Client.DefaultRequestHeaders.Add('Authorization',$Token)
        }
    }
}
function Show-FalconMap {
<#
.SYNOPSIS
Display indicators on the Falcon Intelligence Indicator Map
.DESCRIPTION
Your default web browser will be used to view the Indicator Map.

Show-FalconMap will accept domains, SHA256 hashes, IP addresses and URLs. Invalid indicator values are ignored.
.PARAMETER Indicator
Indicator to display on the Indicator map
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Show-FalconMap
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory,ValueFromPipeline,Position=1)]
        [Alias('Indicators')]
        [string[]]$Indicator
    )
    begin {
        [string]$FalconUI = "$($Script:Falcon.Hostname -replace 'api','falcon')"
        $List = [System.Collections.Generic.List[string]]@()
    }
    process {
        if ($Indicator) {
            @($Indicator).foreach{
                if ($_ -match '^(domain|hash|ip_address|url)_') {
                    # Split indicators from 'Get-FalconIndicator'
                    [string]$String = switch -Regex ($_) {
                        '^domain_' { $_ -replace '_',':' }
                        '^hash_sha256' { @('hash',($_ -split '_')[-1]) -join ':' }
                        '^ip_address_' { $_ -replace '_address_',':' }
                        '^url_' {
                            $Value = ([System.Uri]($_ -replace 'url_',$null)).Host
                            $Type = Test-RegexValue $Value
                            if ($Type -match 'ipv(4|6)') { $Type = 'ip' }
                            if ($Type -and $Value) { @($Type,$Value) -join ':' }
                        }
                    }
                    if ($String) { $List.Add($String) }
                } else {
                    $Type = Test-RegexValue $_
                    if ($Type -match 'ipv(4|6)') { $Type = 'ip' }
                    $Value = if ($Type -match '^(domain|md5|sha256)$') { $_.ToLower() } else { $_ }
                    if ($Type -and $Value) { $List.Add("$($Type):'$Value'") }
                }
            }
        }
    }
    end {
        if ($List) {
            [string[]]$IocInput = @($List | Select-Object -Unique) -join ','
            if (!$IocInput) { throw "No valid indicators found." }
            [string]$Target = "$($FalconUI)/intelligence/graph?indicators=$($IocInput -join ',')"
            if ($PSCmdlet.ShouldProcess($Target)) { Start-Process $Target }
        }
    }
}
function Show-FalconModule {
<#
.SYNOPSIS
Display information about your PSFalcon module
.DESCRIPTION
Outputs an object containing module, user and system version information that is helpful for diagnosing problems
with the PSFalcon module.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Show-FalconModule
#>
    [CmdletBinding()]
    param()
    process {
        $ManifestPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'PSFalcon.psd1'
        if (Test-Path $ManifestPath) {
            $ModuleData = Import-PowerShellDataFile -Path $ManifestPath
            [PSCustomObject]@{
                PSVersion = "$($PSVersionTable.PSEdition) [$($PSVersionTable.PSVersion)]"
                ModuleVersion = "v$($ModuleData.ModuleVersion) {$($ModuleData.GUID)}"
                ModulePath = Split-Path $ManifestPath -Parent
                UserModulePath = $env:PSModulePath
                UserHome = $HOME
                UserAgent = 'crowdstrike-psfalcon',$ModuleData.ModuleVersion -join '/'
            }
        } else {
            throw "Unable to locate '$ManifestPath'."
        }
    }
}