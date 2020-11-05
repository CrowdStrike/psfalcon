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
        # Regex value for [datetime] fields
        $TimeRegex = '(^(first|last)_seen$|^.*_timestamp$|^.*_(applied|assigned)$)'

        # Fields excluded from output
        $Exclusions = @{
            Detection = @('hostinfo', 'behaviors_processed')
            Host = @('policies')
            Incident = @('hosts')
        }
        # TypeNames used to determine formatting
        $TypeNames = @{
            Detection = @('domain.MsaDetectSummariesResponse')
            Host = @('domain.DeviceDetailsResponseSwagger', 'responses.HostGroupMembersV1',
            'responses.PolicyMembersRespV1')
            HostGroup = @('responses.HostGroupsV1')
            Identifier = @('binservclient.MsaPutFileResponse', 'domain.DeviceResponse',
            'domain.SPAPIQueryVulnerabilitiesResponse', 'api.MsaIncidentQueryResponse', 'msa.QueryResponse')
            Incident = @('api.MsaExternalIncidentResponse')
            IOC = @('api.MsaReplyIOCIDs', 'api.MsaReplyIOC')
            Prevention = @('responses.PreventionPoliciesV1')
            PutFile = @('binservclient.MsaPFResponse')
            SensorUpdate = @('responses.SensorUpdatePoliciesV2')
            User = @('domain.UserMetaDataResponse')
            Vulnerability = @('domain.SPAPIVulnerabilitiesEntitiesResponseV2')
        }
        function Add-Field ($Object, $Name, $Value) {
            $Value = if ($Value -and $Name -match $TimeRegex) {
                # Add $TimeRegex values as [datetime]
                [datetime] $Value
            } elseif (($Value -is [object[]]) -and ($Value[0] -is [string])) {
                # Add field and value as [string]
                $Value -join ', '
            } else {
                $Value
            }
            # Add field and value to [PSCustomObject]
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        function Get-SimpleObject ($Object) {
            ($Object.resources).foreach{
                # Output detail array
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
                # Convert detailed detection results
                ($Object.resources).foreach{
                    # Output detail array
                    $Item = [PSCustomObject] @{}

                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'device') {
                            # Add device identifier
                            Add-Field @Param -Name 'device_id' -Value $_.value.device_id
                        } elseif ($_.name -eq 'behaviors') {
                            # Add combined tactic and technique identifiers
                            $TTP = ($_.value).foreach{
                                "$($_.tactic_id):$($_.technique_id)"
                            }
                            Add-Field @Param -Name 'tactic_and_technique' -Value ($TTP -join ', ')
                        } elseif ($_.name -eq 'quarantined_files') {
                            # Add quarantined file identifiers
                            Add-Field @Param -Name 'quarantined_files' -Value $_.value.id
                        } elseif ($Exclusions.Detection -notcontains $_.name) {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.Host -contains $_ } {
                # Convert detailed host results
                ($Object.resources).foreach{
                    # Output detail array
                    $Item = [PSCustomObject] @{}

                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'device_policies') {
                            ($_.value.psobject.properties).foreach{
                                # Add policy type and identifier
                                Add-Field @Param -Name "$($_.name)_id" -Value $_.value.policy_id

                                # Add assigned date
                                Add-Field @Param -Name "$($_.name)_assigned" -Value $_.value.assigned_date

                                # Add applied date
                                $Applied = if ($_.value.applied -eq $true) {
                                    $_.value.applied_date
                                } else {
                                    $null
                                }
                                Add-Field @Param -Name "$($_.name)_applied" -Value $Applied

                                if ($_.value.uninstall_protection) {
                                    # Add uninstall_protection
                                    Add-Field @Param -Name 'uninstall_protection' -Value (
                                        $_.value.uninstall_protection)
                                }
                            }
                        } elseif ($_.name -eq 'meta') {
                            # Add meta version
                            Add-Field @Param -Name "$($_.name)_version" -Value $_.value.version
                        } elseif ($Exclusions.Host -notcontains $_.name) {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.HostGroup -contains $_ } {
                # Convert detailed host group results
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.Identifier -contains $_ } {
                # Output identifier array
                ($Object.resources).foreach{
                    [PSCustomObject] @{
                        id = $_
                    }
                }
            }
            { $TypeNames.Incident -contains $_ } {
                # Convert detailed incident results
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}

                    ($_.psobject.properties).foreach{
                        if ($Exclusions.Incident -notcontains $_.name) {
                            Add-Field  -Object $Item -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.IOC -contains $_ } {
                if ($_ -eq 'api.MsaReplyIOCIDs') {
                    # Output type and value array
                    ($Object.resources).foreach{
                        [PSCustomObject] @{
                            type = ($_).Split(':')[0]
                            value = ($_).Split(':')[1]
                        }
                    }
                } else {
                    # Convert detailed IOC results
                    Get-SimpleObject -Object $Object
                }
            }
            { $TypeNames.Prevention -contains $_ } {
                # Convert detailed Prevention policy results
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}

                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'groups') {
                            # Add groups as [string]
                            Add-Field @Param -Name $_.name -Value ($_.value.id -join ', ')
                        } elseif ($_.name -eq 'prevention_settings') {
                            ($_.value.settings).foreach{
                                if ($_.type -eq 'toggle') {
                                    # Add 'toggle' settings with as [bool]
                                    Add-Field @Param -Name $_.id -Value $_.value.enabled
                                } else {
                                    # Add 'mlslider' settings as [string]
                                    Add-Field @Param -Name $_.id -Value (
                                        "$($_.value.detection):$($_.value.prevention)")
                                }
                            }
                        } else {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.PutFile -contains $_ } {
                # Convert detailed put file results
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.SensorUpdate -contains $_ } {
                # Convert detailed Sensor Update policy results
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}

                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'groups') {
                            # Add group identifiers as [string]
                            Add-Field @Param -Name $_.name -Value ($_.value.id -join ', ')
                        } elseif ($_.name -eq 'settings') {
                            ($_.value.psobject.properties).foreach{
                                # Add settings fields and values
                                Add-Field @Param -Name $_.name -Value $_.value
                            }
                        } else {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            { $TypeNames.User -contains $_ } {
                # Convert detailed user results
                Get-SimpleObject -Object $Object
            }
            { $TypeNames.Vulnerability -contains $_ } {
                # Convert detailed vulnerability results
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}

                    $Param = @{
                        Object = $Item
                    }
                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'cve') {
                            ($_.value.psobject.properties).foreach{
                                # Add fields from 'cve' with 'cve' prefix
                                Add-Field @Param -Name "cve_$($_.name)" -Value $_.value
                            }
                        } elseif ($_.name -eq 'app') {
                            ($_.value.psobject.properties).foreach{
                                # Add fields from 'app'
                                Add-Field @Param -Name $_.name -Value $_.value
                            }
                        } elseif ($_.name -eq 'host_info') {
                            ($_.value.psobject.properties).foreach{
                                if ($_.name -eq 'groups') {
                                    # Add group names as [string]
                                    Add-Field @Param -Name $_.name -Value ($_.value.name -join ', ')
                                } else {
                                    # Add fields from 'host_info'
                                    Add-Field @Param -Name $_.name -Value $_.value
                                }
                            }
                        } elseif ($_.name -eq 'remediation') {
                            # Add remediation identifiers as [string]
                            Add-Field @Param -Name "remediation_ids" -Value ($_.value.ids -join ', ')
                        } else {
                            Add-Field @Param -Name $_.name -Value $_.value
                        }
                    }
                    $Item
                }
            }
            default {
                # Output error for undefined request types
                Write-Error "CSV conversion is not available for this request type"
            }
        }
    }
}