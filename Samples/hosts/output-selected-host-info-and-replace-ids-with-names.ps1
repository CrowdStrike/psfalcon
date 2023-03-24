#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
This script will replace identifiers with the related `name` under each Host result. The fields to include can be
defined under the `Field` variable. The output will be returned in the console.
#>
# Fields to include with the export to CSV (host group and policy data is automatically added)
[string[]]$Field = 'device_id','hostname','last_seen','first_seen','local_ip','external_ip','agent_version'
$Field += 'device_policies','groups'

# Retrieve all host information and filter to selected fields
$HostInfo = Get-FalconHost -Detailed -All | Select-Object $Field
if ($HostInfo) {
    # Create hashtable to store object detail for hosts
    $Related = @{
        DeviceControlPolicy = @{}
        FirewallPolicy = @{}
        IoaGroup = @{}
        PreventionPolicy = @{}
        ResponsePolicy = @{}
        SensorUpdatePolicy = @{}
        HostGroup = @{}
    }
    foreach ($ItemType in $Related.Keys) {
        # Match policy type to the label used with hosts
        [string]$HostLabel = switch ($ItemType) {
            'DeviceControlPolicy' { 'device_control' }
            'HostGroup' { 'groups' }
            'IoaGroup' { 'rule_groups' }
            'ResponsePolicy' { 'remote_response' }
            'SensorUpdatePolicy' { 'sensor_update' }
            default { ($_ -replace 'Policy', $null).ToLower() }
        }
        [string[]]$Id = if ($ItemType -eq 'IoaGroup') {
            # Collect IOA rule group identifiers
            ($HostInfo.device_policies.prevention.rule_groups | Group-Object).Name
        } elseif ($ItemType -match 'Policy$') {
            # Collect policy identifiers
            ($HostInfo.device_policies.$HostLabel.policy_id | Group-Object).Name
        } else {
            # Collect host group identifiers
            ($HostInfo.groups | Group-Object).Name
        }
        # Collect names and identifiers for each item in hashtable
        [object[]]$Content = & "Get-Falcon$($ItemType)" -Id $Id | Select-Object id,name
        if ($Content) {
            @($Content).foreach{ $Related.$ItemType["$($_.id)"] = "$($_.name)" }
        } else {
            Write-Error "Unable to collect '$ItemType' information. Check permissions."
        }
        @($HostInfo).foreach{
            # Define new property names to add to output
            [string]$Name = if ($ItemType -eq 'HostGroup') {
                'host',$HostLabel -join '_'
            } elseif ($ItemType -eq 'IoaGroup') {
                'ioa',$HostLabel -join '_'
            } else {
                $HostLabel,'policy' -join '_'
            }
            $Value = if ($ItemType -eq 'HostGroup') {
                # Replace host group identifiers with names and remove 'groups'
                if ($_.groups) {
                    ($_.groups | ForEach-Object { $Related.$ItemType.$_ }) -join ','
                    [void]$_.PSObject.Properties.Remove('groups')
                }
            } elseif ($ItemType -eq 'IoaGroup') {
                # Replace IOA rule group identifiers with names
                if ($_.device_policies.prevention.rule_groups) {
                    ($_.device_policies.prevention.rule_groups | ForEach-Object {
                        $Related.$ItemType.$_
                    }) -join ','
                }
            } else {
                # Replace policy identifiers with names and add as '<type>_policy'
                if ($_.device_policies.$HostLabel.policy_id){
                    $Related.$ItemType.($_.device_policies.$HostLabel.policy_id)
                }
            }
            $_.PSObject.Properties.Add((New-Object PSNoteProperty($Name,$Value)))
        }
    }
    # Remove redundant 'device_policies' property
    @($HostInfo).Where({ $_.device_policies }).foreach{ [void]$_.PSObject.Properties.Remove('device_policies') }
    $HostInfo
} else {
    Write-Error "Unable to collect Host information. Check permissions."
}