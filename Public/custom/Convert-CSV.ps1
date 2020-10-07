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
            Hosts = @('policies')
        }
        # TypeNames used to determine formatting
        $TypeNames = @{
            Identifiers = @('domain.DeviceResponse', 'domain.SPAPIQueryVulnerabilitiesResponse',
            'msa.QueryResponse')
            Hosts = @('domain.DeviceDetailsResponseSwagger', 'responses.HostGroupMembersV1',
            'responses.PolicyMembersRespV1')
            Vulnerabilities = @('domain.SPAPIVulnerabilitiesEntitiesResponseV2')
        }
        function Add-Field ($Object, $Name, $Value) {
            $Value = if ($Name -match $TimeRegex) {
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
        function Out-Identifier ($Object) {
            # Output identifier array
            ($Object.resources).foreach{
                [PSCustomObject] @{
                    id = $_
                }
            }
        }
    }
    process {
        switch ($Object.PSObject.TypeNames) {
            { $TypeNames.Identifiers -contains $_ } {
                # Output identifier array
                Out-Identifier $Object
            }
            { $TypeNames.Hosts -contains $_ } {
                # Convert detailed 'host' results
                ($Object.resources).foreach{
                    # Output detail array
                    $Item = [PSCustomObject] @{}

                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'device_policies') {
                            ($_.value.psobject.properties).foreach{
                                # Add policy type and identifier
                                Add-Field $Item "$($_.name)_id" $_.value.policy_id

                                # Add assigned date
                                Add-Field $Item "$($_.name)_assigned" $_.value.assigned_date

                                # Add applied date
                                $Applied = if ($_.value.applied -eq $true) {
                                    $_.value.applied_date
                                } else {
                                    $null
                                }
                                Add-Field $Item "$($_.name)_applied" $Applied

                                if ($_.value.uninstall_protection) {
                                    # Add uninstall_protection
                                    Add-Field $Item 'uninstall_protection' $_.value.uninstall_protection
                                }
                            }
                        } elseif ($_.name -eq 'meta') {
                            # Add meta version
                            Add-Field $Item "$($_.name)_version" $_.value.version
                        } elseif ($Exclusions.Hosts -notcontains $_.name) {
                            # Add field and value
                            Add-Field $Item $_.name $_.value
                        }
                    }
                    # Output item
                    $Item
                }
            }
            { $TypeNames.Vulnerabilities -contains $_ } {
                # Convert detailed 'vulnerability' results
                ($Object.resources).foreach{
                    $Item = [PSCustomObject] @{}

                    ($_.psobject.properties).foreach{
                        if ($_.name -eq 'cve') {
                            ($_.value.psobject.properties).foreach{
                                # Add fields from 'cve' with 'cve' prefix
                                Add-Field $Item "cve_$($_.name)" $_.value
                            }
                        } elseif ($_.name -eq 'app') {
                            ($_.value.psobject.properties).foreach{
                                # Add fields from 'app'
                                Add-Field $Item $_.name $_.value
                            }
                        } elseif ($_.name -eq 'host_info') {
                            ($_.value.psobject.properties).foreach{
                                if ($_.name -eq 'groups') {
                                    # Add group names
                                    Add-Field $Item $_.name $_.value.name
                                } else {
                                    # Add fields from 'host_info'
                                    Add-Field $Item $_.name $_.value
                                }
                            }
                        } elseif ($_.name -eq 'remediation') {
                            # Add remediation ids
                            Add-Field $Item "remediation_ids" $_.value.ids
                        } else {
                            # Add field and value
                            Add-Field $Item $_.name $_.value
                        }
                    }
                    # Output item
                    $Item
                }
            }
        }
    }
}