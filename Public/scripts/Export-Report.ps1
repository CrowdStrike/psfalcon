function Export-Report {
    <#
    .SYNOPSIS
        Format a response object and output to CSV
    .PARAMETER PATH
        Output path and file name
    .PARAMETER OBJECT
        A result object to format
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Position = 1,
            Mandatory = $true)]
        [string] $Path,

        [Parameter(
            Position = 2,
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [object] $Object
    )
    begin {
        $TimeRegex = '(^(first|last)_seen$|^.*_timestamp$|^.*_(applied|assigned)$)'
        $Exclusions = @{
            Detection = @('hostinfo', 'behaviors_processed')
            Host      = @('policies')
            Incident  = @('hosts')
        }
        $TypeNames = @{
            Detection     = @('domain.MsaDetectSummariesResponse')
            DeviceControl = @('responses.DeviceControlPoliciesV1')
            Firewall      = @('responses.FirewallPoliciesV1')
            Host          = @('domain.DeviceDetailsResponseSwagger', 'responses.HostGroupMembersV1',
                            'responses.PolicyMembersRespV1')
            HostGroup     = @('responses.HostGroupsV1')
            Identifier    = @('binservclient.MsaPutFileResponse', 'domain.DeviceResponse',
                            'domain.SPAPIQueryVulnerabilitiesResponse', 'api.MsaIncidentQueryResponse',
                            'msa.QueryResponse')
            Incident      = @('api.MsaExternalIncidentResponse')
            IOC           = @('api.MsaReplyIOCIDs', 'api.MsaReplyIOC')
            Prevention    = @('responses.PreventionPoliciesV1')
            PutFile       = @('binservclient.MsaPFResponse')
            SensorUpdate  = @('responses.SensorUpdatePoliciesV2')
            User          = @('domain.UserMetaDataResponse')
            Vulnerability = @('domain.SPAPIVulnerabilitiesEntitiesResponseV2')
        }
        function Add-Field ($Object, $Name, $Value) {
            $Value = if ($Value -and $Name -match $TimeRegex) {
                [datetime] $Value
            }
            elseif (($Value -is [object[]]) -and ($Value[0] -is [string])) {
                $Value -join ', '
            }
            else {
                $Value
            }
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        function Get-SimpleObject ($Object) {
            ($Object).foreach{
                $Item = [PSCustomObject] @{}
                ($_.PSObject.Properties).foreach{
                    Add-Field -Object $Item -Name $_.Name -Value $_.Value
                }
                $Item
            }
        }
    }
    process {
        $Output = switch ($Meta.PSObject.TypeNames | Where-Object { $_ -notmatch '^System.*$' }) {
            { $TypeNames.Detection -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.PSObject.Properties).foreach{
                        if ($_.Name -eq 'device') {
                            Add-Field @Param -Name 'device_id' -Value $_.Value.device_id
                        }
                        elseif ($_.Name -eq 'behaviors') {
                            $TTP = ($_.Value).foreach{
                                "$($_.tactic_id):$($_.technique_id)"
                            }
                            Add-Field @Param -Name 'tactic_and_technique' -Value ($TTP -join ', ')
                        }
                        elseif ($_.Name -eq 'quarantined_files') {
                            Add-Field @Param -Name 'quarantined_files' -Value $_.Value.id
                        }
                        elseif ($Exclusions.Detection -notcontains $_.Name) {
                            Add-Field @Param -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.DeviceControl -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.PSObject.Properties).foreach{
                        if ($_.Name -eq 'groups') {
                            Add-Field @Param -Name $_.Name -Value ($_.Value.id -join ', ')
                        }
                        elseif ($_.Name -eq 'settings') {
                            Add-Field @Param -Name 'enforcement_mode' -Value $_.Value.enforcement_mode
                            Add-Field @Param -Name 'end_user_notification' -Value $_.Value.end_user_notification
                        }
                        else {
                            Add-Field @Param -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.Firewall -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.PSObject.Properties).foreach{
                        if ($_.Name -eq 'groups') {
                            Add-Field @Param -Name $_.Name -Value ($_.Value.id -join ', ')
                        }
                        else {
                            Add-Field @Param -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.Host -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.PSObject.Properties).foreach{
                        if ($_.Name -eq 'device_policies') {
                            ($_.Value.psobject.properties).foreach{
                                Add-Field @Param -Name "$($_.Name)_id" -Value $_.Value.policy_id
                                Add-Field @Param -Name "$($_.Name)_assigned" -Value $_.Value.assigned_date
                                $Applied = if ($_.Value.applied -eq $true) {
                                    $_.Value.applied_date
                                }
                                else {
                                    $null
                                }
                                Add-Field @Param -Name "$($_.Name)_applied" -Value $Applied
                                if ($_.Value.uninstall_protection) {
                                    Add-Field @Param -Name 'uninstall_protection' -Value (
                                        $_.Value.uninstall_protection)
                                }
                            }
                        }
                        elseif ($_.Name -eq 'meta') {
                            Add-Field @Param -Name "$($_.Name)_version" -Value $_.Value.version
                        }
                        elseif ($Exclusions.Host -notcontains $_.Name) {
                            Add-Field @Param -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.HostGroup -contains $_ } {
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.Identifier -contains $_ } {
                ($Object).foreach{
                    [PSCustomObject] @{
                        id = $_
                    }
                }
            }
            { $TypeNames.Incident -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    ($_.PSObject.Properties).foreach{
                        if ($Exclusions.Incident -notcontains $_.Name) {
                            Add-Field -Object $Item -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.IOC -contains $_ } {
                if ($_ -eq 'api.MsaReplyIOCIDs') {
                    ($Object).foreach{
                        [PSCustomObject] @{
                            type  = ($_).Split(':')[0]
                            value = ($_).Split(':')[1]
                        }
                    }
                }
                else {
                    Get-SimpleObject -Object $Object
                }
            }
            { $TypeNames.Prevention -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.PSObject.Properties).foreach{
                        if ($_.Name -eq 'groups') {
                            Add-Field @Param -Name $_.Name -Value ($_.Value.id -join ', ')
                        }
                        elseif ($_.Name -eq 'prevention_settings') {
                            ($_.Value.settings).foreach{
                                if ($_.type -eq 'toggle') {
                                    Add-Field @Param -Name $_.id -Value $_.Value.enabled
                                }
                                else {
                                    Add-Field @Param -Name $_.id -Value (
                                        "$($_.Value.detection):$($_.Value.prevention)")
                                }
                            }
                        }
                        else {
                            Add-Field @Param -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.PutFile -contains $_ } {
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.SensorUpdate -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.PSObject.Properties).foreach{
                        if ($_.Name -eq 'groups') {
                            Add-Field @Param -Name $_.Name -Value ($_.Value.id -join ', ')
                        }
                        elseif ($_.Name -eq 'settings') {
                            ($_.Value.psobject.properties).foreach{
                                Add-Field @Param -Name $_.Name -Value $_.Value
                            }
                        }
                        else {
                            Add-Field @Param -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.User -contains $_ } {
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.Vulnerability -contains $_ } {
                ($Object).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.PSObject.Properties).foreach{
                        if ($_.Name -eq 'cve') {
                            ($_.Value.psobject.properties).foreach{
                                Add-Field @Param -Name "cve_$($_.Name)" -Value $_.Value
                            }
                        }
                        elseif ($_.Name -eq 'app') {
                            ($_.Value.psobject.properties).foreach{
                                Add-Field @Param -Name $_.Name -Value $_.Value
                            }
                        }
                        elseif ($_.Name -eq 'host_info') {
                            ($_.Value.psobject.properties).foreach{
                                if ($_.Name -eq 'groups') {
                                    Add-Field @Param -Name $_.Name -Value ($_.Value.name -join ', ')
                                }
                                else {
                                    Add-Field @Param -Name $_.Name -Value $_.Value
                                }
                            }
                        }
                        elseif ($_.Name -eq 'remediation') {
                            Add-Field @Param -Name "remediation_ids" -Value ($_.Value.ids -join ', ')
                        }
                        else {
                            Add-Field @Param -Name $_.Name -Value $_.Value
                        }
                    }
                    $Item
                }
            }
        }
        if ($Output) {
            $Output | Export-Csv -Path $Path -NoTypeInformation -Append
        }
        else {
            Write-Error "CSV conversion is not available for this request type"
        }
    }
}