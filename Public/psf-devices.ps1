function Add-FalconSensorTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [array] $Tags,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 3)]
        [boolean] $QueueOffline
    )
    begin {
        $Properties = @('cid', 'device_id', 'platform_name', 'hostname')
    }
    process {
        $Scripts = @{
            Linux   = '-Raw=```echo "IwAhAC8AYgBpAG4ALwBiAGEAcwBoAAoASQBGAFMAPQAsAAoAcgBlAGEAZAAgAC0AcgBhACAAdAB' +
                'hAGcAcwAgADwAPAA8ACAAIgAkACgALwBvAHAAdAAvAEMAcgBvAHcAZABTAHQAcgBpAGsAZQAvAGYAYQBsAGMAbwBuAGMAdA' +
                'BsACAALQBnACAALQAtAHQAYQBnAHMAIAB8ACAAcwBlAGQAIAAnAHMALwBeAFMAZQBuAHMAbwByACAAZwByAG8AdQBwAGkAb' +
                'gBnACAAdABhAGcAcwAgAGEAcgBlACAAbgBvAHQAIABzAGUAdAAvAC8AOwAgAHMALwBeAHQAYQBnAHMAPQAvAC8AOwAgAHMA' +
                'LwAuACQALwAvACcAKQAsACQAMQAiAAoASQBGAFMAPQAkACcAXABuACcACgB1AG4AaQBxAHUAZQA9ACgAYABmAG8AcgAgAFQ' +
                'AQQBHACAAaQBuACAAIgAkAHsAdABhAGcAcwBbAEAAXQB9ACIAOwAgAGQAbwAgAGUAYwBoAG8AIAAiACQAVABBAEcAIgA7AC' +
                'AAZABvAG4AZQAgAHwAIABzAG8AcgB0ACAALQB1AGAAKQAKAC8AbwBwAHQALwBDAHIAbwB3AGQAUwB0AHIAaQBrAGUALwBmA' +
                'GEAbABjAG8AbgBjAHQAbAAgAC0AZAAgAC0AZgAgAC0ALQB0AGEAZwBzAAoASQBGAFMAPQAsAAoALwBvAHAAdAAvAEMAcgBv' +
                'AHcAZABTAHQAcgBpAGsAZQAvAGYAYQBsAGMAbwBuAGMAdABsACAALQBzACAALQAtAHQAYQBnAHMAPQAiACQAewB1AG4AaQB' +
                'xAHUAZQBbACoAXQB9ACIACgAvAG8AcAB0AC8AQwByAG8AdwBkAFMAdAByAGkAawBlAC8AZgBhAGwAYwBvAG4AYwB0AGwAIA' +
                'AtAGcAIAAtAC0AdABhAGcAcwAgAHwAIABzAGUAZAAgACcAcwAvAF4AUwBlAG4AcwBvAHIAIABnAHIAbwB1AHAAaQBuAGcAI' +
                'AB0AGEAZwBzACAAYQByAGUAIABuAG8AdAAgAHMAZQB0AC8ALwA7ACAAcwAvAF4AdABhAGcAcwA9AC8ALwA7ACAAcwAvAC4A' +
                'JAAvAC8AJwA=" | base64 --decode | bash -s "'
            Mac     = ''
            Windows = '-Raw=```$Key = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b8' +
                '8d}\{16e0423f-7058-48c9-a204-725362b67639}\Default"; $Tags = (reg query $Key) -match "GroupingT' +
                'ags"; $Value = if ($Tags) { ($Tags.Split("REG_SZ")[-1].Trim().Split(",") + $args.Split(",") | S' +
                'elect-Object -Unique) -join "," } else { $args }; [void] (reg add $Key /v GroupingTags /d $Valu' +
                'e /f); Write-Output "$(((reg query $Key) -match "GroupingTags").Split("REG_SZ")[-1].Trim())"```' +
                ' -CommandLine="'
        }
        try {
            # Get device info to determine script and begin session
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object $Properties
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            $Request = if ($Init.session_id) {
                $CmdParam = @{
                    # Send 'runscript' with tag values
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = switch ($HostInfo.platform_name) {
                        'Linux'   { "$($Scripts.$_)$($PSBoundParameters.Tags -join ',')" + '"```' }
                        'Mac'     { $null }
                        'Windows' { "$($Scripts.$_)'$($PSBoundParameters.Tags -join ',')'`"" }
                    }
                }
                Invoke-FalconAdminCommand @CmdParam
            }
            if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                do {
                    # Retry 'runscript' confirmation until result is provided
                    Start-Sleep -Seconds 5
                    $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                } until (
                    $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                )
                @($HostInfo | Select-Object cid, device_id, hostname).foreach{
                    # Output device properties and 'tags' value
                    $Value = if ($Confirm.stdout) {
                        ($Confirm.stdout).Trim()
                    } else {
                        $Confirm.stderr
                    }
                    Add-Property -Object $_ -Name 'tags' -Value $Value
                    $_
                }
            } else {
                $Request
            }
        } catch {
            throw $_
        }
    }
}
function Find-FalconDuplicate {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [array] $Hosts,

        [Parameter(Position = 2)]
        [ValidateSet('external_ip', 'local_ip', 'mac_address', 'os_version', 'platform_name', 'serial_number')]
        [string] $Filter
    )
    begin {
        function Group-Selection ($Object, $GroupBy) {
            ($Object | Group-Object $GroupBy).Where({ $_.Count -gt 1 -and $_.Name }).foreach{
                $_.Group | Sort-Object last_seen | Select-Object -First ($_.Count - 1)
            }
        }
        # Comparison criteria and required properties for host results
        $Criteria = @('cid', 'hostname')
        $Required = @('cid', 'device_id', 'first_seen', 'last_seen', 'hostname')
        if ($PSBoundParameters.Filter) {
            $Criteria += $PSBoundParameters.Filter
            $Required += $PSBoundParameters.Filter
        }
        # Create filter for excluding results with empty $Criteria values
        $FilterScript = { (($Criteria).foreach{ "`$_.$($_)" }) -join ' -and ' }
    }
    process {
        $HostArray = if (!$PSBoundParameters.Hosts) {
            # Retreive Host details
            Get-FalconHost -Detailed -All
        } else {
            $PSBoundParameters.Hosts
        }
        ($Required).foreach{
            if (($HostArray | Get-Member -MemberType NoteProperty).Name -notcontains $_) {
                # Verify required properties are present
                throw "Missing required property '$_'."
            }
        }
        # Group, sort and output result
        $Param = @{
            Object  = $HostArray | Select-Object $Required | Where-Object -FilterScript $FilterScript
            GroupBy = $Criteria
        }
        $Output = Group-Selection @Param
    }
    end {
        if ($Output) {
            $Output
        } else {
            Write-Warning "No duplicates found."
        }
    }
}
function Get-FalconSensorTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 2)]
        [boolean] $QueueOffline
    )
    begin {
        $Properties = @('cid', 'device_id', 'platform_name', 'hostname')
    }
    process {
        $Scripts = @{
            Linux = '-Raw=```echo "IwAhAC8AYgBpAG4ALwBiAGEAcwBoAAoALwBvAHAAdAAvAEMAcgBvAHcAZABTAHQAcgBpAGsAZQAvA' +
                'GYAYQBsAGMAbwBuAGMAdABsACAALQBnACAALQAtAHQAYQBnAHMAIAB8ACAAcwBlAGQAIAAnAHMALwBeAFMAZQBuAHMAbwBy' +
                'ACAAZwByAG8AdQBwAGkAbgBnACAAdABhAGcAcwAgAGEAcgBlACAAbgBvAHQAIABzAGUAdAAuAC8ALwA7ACAAcwAvAF4AdAB' +
                'hAGcAcwA9AC8ALwA7ACAAcwAvAC4AJAAvAC8AJwA=" | base64 --decode | bash```'
            Mac     = '' # '/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^tags=//; s/.$//"'
            Windows = '-Raw=```powershell.exe -enc "JABUAGEAZwBzACAAPQAgACgAcgBlAGcAIABxAHUAZQByAHkAIAAnAEgASwBF' +
                'AFkAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAFwAUwBZAFMAVABFAE0AXABDAHIAbwB3AGQAUwB0AHIAaQBrAGUAXAB' +
                '7ADkAYgAwADMAYwAxAGQAOQAtADMAMQAzADgALQA0ADQAZQBkAC0AOQBmAGEAZQAtAGQAOQBmADQAYwAwADMANABiADgAOA' +
                'BkAH0AXAB7ADEANgBlADAANAAyADMAZgAtADcAMAA1ADgALQA0ADgAYwA5AC0AYQAyADAANAAtADcAMgA1ADMANgAyAGIAN' +
                'gA3ADYAMwA5AH0AXABEAGUAZgBhAHUAbAB0ACcAKQAgAC0AbQBhAHQAYwBoACAAJwBHAHIAbwB1AHAAaQBuAGcAVABhAGcA' +
                'cwAnADsAIABpAGYAIAAoACQAVABhAGcAcwApACAAewAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgAkACgAJABUAGE' +
                'AZwBzAC4AUwBwAGwAaQB0ACgAIgBSAEUARwBfAFMAWgAiACkAWwAtADEAXQAuAFQAcgBpAG0AKAApACkAIgAgAH0A"```'
        }
        try {
            # Get device info to determine script and begin session
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object $Properties
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            $Request = if ($Init.session_id) {
                # Send 'runscript'
                $CmdParam = @{
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = "$($Scripts.($HostInfo.platform_name))"
                }
                Invoke-FalconAdminCommand @CmdParam
            }
            if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                do {
                    # Retry 'runscript' confirmation until result is provided
                    Start-Sleep -Seconds 5
                    $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                } until (
                    $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                )
                @($HostInfo | Select-Object cid, device_id, hostname).foreach{
                    # Output device properties and 'tags' value
                    $Value = if ($Confirm.stdout) {
                        ($Confirm.stdout).Trim()
                    } else {
                        $Confirm.stderr
                    }
                    Add-Property -Object $_ -Name 'tags' -Value $Value
                    $_
                }
            } else {
                $Request
            }
        } catch {
            throw $_
        }
    }
}
function Remove-FalconSensorTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({
            @($_).foreach{
                if ((Test-RegexValue $_) -eq 'tag') {
                    $true
                } else {
                    throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
                }
            }
        })]
        [array] $Tags,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 3)]
        [boolean] $QueueOffline
    )
    begin {
        $Properties = @('cid', 'device_id', 'platform_name', 'hostname')
    }
    process {
        $Scripts = @{
            Linux   = '-Raw=```echo "IwAhAC8AYgBpAG4ALwBiAGEAcwBoAAoASQBGAFMAPQAsAAoAcgBlAGEAZAAgAC0AcgBhACAAZAB' +
                'lAGwAZQB0AGUAIAA8ADwAPAAgACIAJAAxACIACgByAGUAYQBkACAALQByAGEAIAB0AGEAZwBzACAAPAA8ADwAIAAiACQAKA' +
                'AvAG8AcAB0AC8AQwByAG8AdwBkAFMAdAByAGkAawBlAC8AZgBhAGwAYwBvAG4AYwB0AGwAIAAtAGcAIAAtAC0AdABhAGcAc' +
                'wAgAHwAIABzAGUAZAAgACcAcwAvAF4AUwBlAG4AcwBvAHIAIABnAHIAbwB1AHAAaQBuAGcAIAB0AGEAZwBzACAAYQByAGUA' +
                'IABuAG8AdAAgAHMAZQB0AC4ALwAvADsAIABzAC8AXgB0AGEAZwBzAD0ALwAvADsAIABzAC8ALgAkAC8ALwAnACkAIgAKAGk' +
                'AZgAgACgAKAAgACQAewAjAHQAYQBnAHMAWwBAAF0AfQAgACkAKQA7ACAAdABoAGUAbgAKACAAIAAvAG8AcAB0AC8AQwByAG' +
                '8AdwBkAFMAdAByAGkAawBlAC8AZgBhAGwAYwBvAG4AYwB0AGwAIAAtAGQAIAAtAGYAIAAtAC0AdABhAGcAcwAKACAAIABmA' +
                'G8AcgAgAGQAZQBsACAAaQBuACAAJAB7AGQAZQBsAGUAdABlAFsAQABdAH0AOwAgAGQAbwAKACAAIAAgACAAdABhAGcAcwA9' +
                'ACgAIgAkAHsAdABhAGcAcwBbAEAAXQAvACQAZABlAGwAfQAiACkACgAgACAAZABvAG4AZQAKACAAIABpAGYAIAAoACgAIAA' +
                'kAHsAIwB0AGEAZwBzAFsAQABdAH0AIAApACkAOwAgAHQAaABlAG4ACgAgACAAIAAgAHYAYQBsAHUAZQA9ACQAKABlAGMAaA' +
                'BvACAAIgAkAHsAdABhAGcAcwBbACoAXQB9ACIAIAB8ACAAcwBlAGQAIAAnAHMALwBeACwALwAvADsAIABzAC8ALABcACsAL' +
                'wAsAC8AOwAgAHMALwAsACQALwAvACcAKQAKACAAIAAgACAALwBvAHAAdAAvAEMAcgBvAHcAZABTAHQAcgBpAGsAZQAvAGYA' +
                'YQBsAGMAbwBuAGMAdABsACAALQBzACAALQAtAHQAYQBnAHMAPQAiACQAewB2AGEAbAB1AGUAWwAqAF0AfQAiAAoAIAAgACA' +
                'AIAAvAG8AcAB0AC8AQwByAG8AdwBkAFMAdAByAGkAawBlAC8AZgBhAGwAYwBvAG4AYwB0AGwAIAAtAGcAIAAtAC0AdABhAG' +
                'cAcwAgAHwAIABzAGUAZAAgACcAcwAvAF4AUwBlAG4AcwBvAHIAIABnAHIAbwB1AHAAaQBuAGcAIAB0AGEAZwBzACAAYQByA' +
                'GUAIABuAG8AdAAgAHMAZQB0AC4ALwAvADsAIABzAC8AXgB0AGEAZwBzAD0ALwAvADsAIABzAC8ALgAkAC8ALwAnAAoAIAAg' +
                'AGYAaQAKAGUAbABzAGUACgAgACAAZQBjAGgAbwAgACIAJAB7AHQAYQBnAHMAWwAqAF0AfQAiAAoAZgBpAA==" | base64 ' +
                '--decode | bash -s "'
            Mac     = ''
            Windows = '-Raw=```$Key = "HKEY_LOCAL_MACHINE\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b8' +
                '8d}\{16e0423f-7058-48c9-a204-725362b67639}\Default"; $Tags = (reg query $Key) -match "GroupingT' +
                'ags"; if ($Tags) { $Delete = $args.Split(","); $Value = $Tags.Split("REG_SZ")[-1].Trim().Split(' +
                '",").Where({ $Delete -notcontains $_ }) -join ","; if ($Value) { [void] (reg add $Key /v Groupi' +
                'ngTags /d $Value /f) } else { [void] (reg delete $Key /v GroupingTags /f) }}; $Tags = (reg quer' +
                'y $Key) -match "GroupingTags"; if ($Tags) { $Tags.Split("REG_SZ")[-1].Trim() }``` -CommandLine="'
        }
        try {
            # Get device info to determine script and begin session
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object $Properties
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            $Request = if ($Init.session_id) {
                $CmdParam = @{
                    # Send 'runscript' with tag values
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = switch ($HostInfo.platform_name) {
                        'Linux'   { "$($Scripts.$_)$($PSBoundParameters.Tags -join ',')" + '"```' }
                        'Mac'     { $null }
                        'Windows' { "$($Scripts.$_)'$($PSBoundParameters.Tags -join ',')'`"" }
                    }
                }
                Invoke-FalconAdminCommand @CmdParam
            }
            if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                do {
                    # Retry 'runscript' confirmation until result is provided
                    Start-Sleep -Seconds 5
                    $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                } until (
                    $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                )
                @($HostInfo | Select-Object cid, device_id, hostname).foreach{
                    # Output device properties and 'tags' value
                    $Value = if ($Confirm.stdout) {
                        ($Confirm.stdout).Trim()
                    } else {
                        $Confirm.stderr
                    }
                    Add-Property -Object $_ -Name 'tags' -Value $Value
                    $_
                }
            } else {
                $Request
            }
        } catch {
            throw $_
        }
    }
}
function Uninstall-FalconSensor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $Id,

        [Parameter(Position = 2)]
        [boolean] $QueueOffline
    )
    begin {
        $Properties = @('cid', 'device_id', 'platform_name', 'device_policies', 'hostname')
    }
    process {
        try {
            $HostInfo = Get-FalconHost -Ids $PSBoundParameters.Id | Select-Object $Properties
            $IdValue = switch ($HostInfo.device_policies.sensor_update.uninstall_protection) {
                'ENABLED'          { $HostInfo.device_id }
                'MAINTENANCE_MODE' { 'MAINTENANCE' }
            }
            $Token = if ($IdValue) {
                (Get-FalconUninstallToken -DeviceId $IdValue -AuditMessage (
                    "Uninstall-FalconSensor [$((Show-FalconModule).UserAgent)]")).uninstall_token
            }
            $InitParam = @{
                HostId       = $HostInfo.device_id
                QueueOffline = if ($PSBoundParameters.QueueOffline -eq $true) {
                    $true
                } else {
                    $false
                }
            }
            $Init = Start-FalconSession @InitParam
            if ($Init.session_id) {
                $Scripts = @{
                    Linux   = ''
                    Mac     = ''
                    Windows = '-Raw=```Start-Sleep -Seconds 5; $RegPath = if ((Get-WmiObject win32_operatingsyst' +
                        'em).osarchitecture -eq "64-bit") { "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\Curren' +
                        'tVersion\Uninstall" } else { "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' +
                        '" }; if (Test-Path $RegPath) { $RegKey = Get-ChildItem $RegPath | Where-Object { $_.Get' +
                        'Value("DisplayName") -like "*CrowdStrike Windows Sensor*" }; if ($RegKey) { $UninstallS' +
                        'tring = $RegKey.GetValue("QuietUninstallString"); $Arguments = @("/c", $UninstallString' +
                        '); if ($args) { $Arguments += "MAINTENANCE_TOKEN=$args" }; $ArgumentList = $Arguments -' +
                        'join " "; Start-Process -FilePath cmd.exe -ArgumentList $ArgumentList -PassThru | Selec' +
                        't-Object Id, ProcessName | ForEach-Object { Write-Output "$($_ | ConvertTo-Json -Compre' +
                        'ss)" }}} else { Write-Error "Unable to locate $RegPath" }```'
                }
                $CmdParam = @{
                    SessionId = $Init.session_id
                    Command   = 'runscript'
                    Arguments = if ($Token -and $HostInfo.platform_name -eq 'Windows') {
                        "$($Scripts.($HostInfo.platform_name)) -CommandLine=`"$Token`""
                    } elseif ($Token) {
                        "$($Scripts.($HostInfo.platform_name)) -s `"$Token`""
                    } else {
                        "$($Scripts.($HostInfo.platform_name))"
                    }
                }
                $Request = Invoke-FalconAdminCommand @CmdParam
                if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                    do {
                        Start-Sleep -Seconds 5
                        $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                    } until (
                        $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                    )
                    @($HostInfo | Select-Object cid, device_id, hostname).foreach{
                        $Status = if ($Confirm.stdout) {
                            @($Confirm.stdout | ConvertFrom-Json).foreach{
                                "[$($_.Id)] '$($_.ProcessName)' started removal of the Falcon sensor"
                            }
                        } else {
                            $Confirm.stderr
                        }
                        Add-Property -Object $_ -Name 'status' -Value $Status
                        $_
                    }
                } else {
                    $Request
                }
            }
        } catch {
            throw $_
        }
    }
}