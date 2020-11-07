function Convert-CSV {
    <#
    .SYNOPSIS
        Format a response object to be CSV-compatible
    .PARAMETER OBJECT
        A result object to format
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'ConvertCSV')]
    [OutputType()]
    param(
        [Parameter(
            Position = 1,
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
            Host          = @('domain.DeviceDetailsResponseSwagger', 'responses.HostGroupMembersV1',
                'responses.PolicyMembersRespV1')
            HostGroup     = @('responses.HostGroupsV1')
            Identifier    = @('binservclient.MsaPutFileResponse', 'domain.DeviceResponse',
                'domain.SPAPIQueryVulnerabilitiesResponse', 'api.MsaIncidentQueryResponse', 'msa.QueryResponse')
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
            ($Object.resources).foreach{
                $Item = [PSCustomObject] @{}
                ($_.psobject.properties).foreach{
                    Add-Field -Object $Item -Name $_.name -Value $_.value
                }
                $Item
            }
        }
    }
    process {
        switch ($Object.PSObject.TypeNames | Where-Object { $_ -notmatch '^System.*$' }) {
            { $TypeNames.Detection -contains $_ } {
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'device') {
                            Add-Field @Param -Name 'device_id' -Value $_.value.device_id
                        }
                        elseif ($_.name -eq 'behaviors') {
                            $TTP = ($_.value).foreach{
                                "$($_.tactic_id):$($_.technique_id)"
                            }
                            Add-Field @Param -Name 'tactic_and_technique' -Value ($TTP -join ', ')
                        }
                        elseif ($_.name -eq 'quarantined_files') {
                            Add-Field @Param -Name 'quarantined_files' -Value $_.value.id
                        }
                        elseif ($Exclusions.Detection -notcontains $_.name) {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.Host -contains $_ } {
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'device_policies') {
                            ($_.value.psobject.properties).foreach{
                                Add-Field @Param -Name "$($_.name)_id" -Value $_.value.policy_id
                                Add-Field @Param -Name "$($_.name)_assigned" -Value $_.value.assigned_date
                                $Applied = if ($_.value.applied -eq $true) {
                                    $_.value.applied_date
                                }
                                else {
                                    $null
                                }
                                Add-Field @Param -Name "$($_.name)_applied" -Value $Applied
                                if ($_.value.uninstall_protection) {
                                    Add-Field @Param -Name 'uninstall_protection' -Value (
                                        $_.value.uninstall_protection)
                                }
                            }
                        }
                        elseif ($_.name -eq 'meta') {
                            Add-Field @Param -Name "$($_.name)_version" -Value $_.value.version
                        }
                        elseif ($Exclusions.Host -notcontains $_.name) {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.HostGroup -contains $_ } {
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.Identifier -contains $_ } {
                ($Object.resources).foreach{
                    [PSCustomObject] @{
                        id = $_
                    }
                }
            }
            { $TypeNames.Incident -contains $_ } {
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}
                    ($_.psobject.properties).foreach{
                        if ($Exclusions.Incident -notcontains $_.name) {
                            Add-Field -Object $Item -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.IOC -contains $_ } {
                if ($_ -eq 'api.MsaReplyIOCIDs') {
                    ($Object.resources).foreach{
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
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'groups') {
                            Add-Field @Param -Name $_.name -Value ($_.value.id -join ', ')
                        }
                        elseif ($_.name -eq 'prevention_settings') {
                            ($_.value.settings).foreach{
                                if ($_.type -eq 'toggle') {
                                    Add-Field @Param -Name $_.id -Value $_.value.enabled
                                }
                                else {
                                    Add-Field @Param -Name $_.id -Value (
                                        "$($_.value.detection):$($_.value.prevention)")
                                }
                            }
                        }
                        else {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.PutFile -contains $_ } {
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.SensorUpdate -contains $_ } {
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'groups') {
                            Add-Field @Param -Name $_.name -Value ($_.value.id -join ', ')
                        }
                        elseif ($_.name -eq 'settings') {
                            ($_.value.psobject.properties).foreach{
                                Add-Field @Param -Name $_.name -Value $_.value
                            }
                        }
                        else {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.User -contains $_ } {
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.Vulnerability -contains $_ } {
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}
                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'cve') {
                            ($_.value.psobject.properties).foreach{
                                Add-Field @Param -Name "cve_$($_.name)" -Value $_.value
                            }
                        }
                        elseif ($_.name -eq 'app') {
                            ($_.value.psobject.properties).foreach{
                                Add-Field @Param -Name $_.name -Value $_.value
                            }
                        }
                        elseif ($_.name -eq 'host_info') {
                            ($_.value.psobject.properties).foreach{
                                if ($_.name -eq 'groups') {
                                    Add-Field @Param -Name $_.name -Value ($_.value.name -join ', ')
                                }
                                else {
                                    Add-Field @Param -Name $_.name -Value $_.value
                                }
                            }
                        }
                        elseif ($_.name -eq 'remediation') {
                            Add-Field @Param -Name "remediation_ids" -Value ($_.value.ids -join ', ')
                        }
                        else {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            default {
                Write-Error "CSV conversion is not available for this request type"
            }
        }
    }
}