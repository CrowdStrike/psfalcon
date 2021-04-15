function Export-Report {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:ExportReport')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $PSBoundParameters.Help) {
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
                $Object | ForEach-Object {
                    $Item = [PSCustomObject] @{}
                    $_.PSObject.Properties | ForEach-Object {
                        Add-Field -Object $Item -Name $_.Name -Value $_.Value
                    }
                    $Item
                }
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Output = switch (($Meta.PSObject.TypeNames).Where({ $_ -notmatch '^System.*$' })) {
                { $TypeNames.Detection -contains $_ } {
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $Param = @{
                            Object = $Item
                        }
                        $_.PSObject.Properties | ForEach-Object {
                            if ($_.Name -eq 'device') {
                                Add-Field @Param -Name 'device_id' -Value $_.Value.device_id
                            }
                            elseif ($_.Name -eq 'behaviors') {
                                $TTP = $_.Value | ForEach-Object {
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
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $Param = @{
                            Object = $Item
                        }
                        $_.PSObject.Properties | ForEach-Object {
                            if ($_.Name -eq 'groups') {
                                Add-Field @Param -Name $_.Name -Value ($_.Value.id -join ', ')
                            }
                            elseif ($_.Name -eq 'settings') {
                                Add-Field @Param -Name 'enforcement_mode' -Value $_.Value.enforcement_mode
                                Add-Field @Param -Name 'end_user_notification' -Value
                                    $_.Value.end_user_notification
                            }
                            else {
                                Add-Field @Param -Name $_.Name -Value $_.Value
                            }
                        }
                        $Item
                    }
                }
                { $TypeNames.Firewall -contains $_ } {
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $Param = @{
                            Object = $Item
                        }
                        $_.PSObject.Properties | ForEach-Object {
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
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $Param = @{
                            Object = $Item
                        }
                        $_.PSObject.Properties | ForEach-Object {
                            if ($_.Name -eq 'device_policies') {
                                $_.Value.psobject.properties | ForEach-Object {
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
                    Get-SimpleObject -Object $PSBoundParameters.Object
                }
                { $TypeNames.Identifier -contains $_ } {
                    $PSBoundParameters.Object | ForEach-Object {
                        [PSCustomObject] @{
                            id = $_
                        }
                    }
                }
                { $TypeNames.Incident -contains $_ } {
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $_.PSObject.Properties | ForEach-Object {
                            if ($Exclusions.Incident -notcontains $_.Name) {
                                Add-Field -Object $Item -Name $_.Name -Value $_.Value
                            }
                        }
                        $Item
                    }
                }
                { $TypeNames.IOC -contains $_ } {
                    if ($_ -eq 'api.MsaReplyIOCIDs') {
                        $PSBoundParameters.Object | ForEach-Object {
                            [PSCustomObject] @{
                                type  = ($_).Split(':')[0]
                                value = ($_).Split(':')[1]
                            }
                        }
                    }
                    else {
                        Get-SimpleObject -Object $PSBoundParameters.Object
                    }
                }
                { $TypeNames.Prevention -contains $_ } {
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $Param = @{
                            Object = $Item
                        }
                        $_.PSObject.Properties | ForEach-Object {
                            if ($_.Name -eq 'groups') {
                                Add-Field @Param -Name $_.Name -Value ($_.Value.id -join ', ')
                            }
                            elseif ($_.Name -eq 'prevention_settings') {
                                $_.Value.settings | ForEach-Object {
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
                    Get-SimpleObject -Object $PSBoundParameters.Object
                }
                { $TypeNames.SensorUpdate -contains $_ } {
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $Param = @{
                            Object = $Item
                        }
                        $_.PSObject.Properties | ForEach-Object {
                            if ($_.Name -eq 'groups') {
                                Add-Field @Param -Name $_.Name -Value ($_.Value.id -join ', ')
                            }
                            elseif ($_.Name -eq 'settings') {
                                $_.Value.psobject.properties | ForEach-Object {
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
                    Get-SimpleObject -Object $PSBoundParameters.Object
                }
                { $TypeNames.Vulnerability -contains $_ } {
                    $PSBoundParameters.Object | ForEach-Object {
                        $Item = [PSCustomObject] @{}
                        $Param = @{
                            Object = $Item
                        }
                        $_.PSObject.Properties | ForEach-Object {
                            if ($_.Name -eq 'cve') {
                                $_.Value.psobject.properties | ForEach-Object {
                                    Add-Field @Param -Name "cve_$($_.Name)" -Value $_.Value
                                }
                            }
                            elseif ($_.Name -eq 'app') {
                                $_.Value.psobject.properties | ForEach-Object {
                                    Add-Field @Param -Name $_.Name -Value $_.Value
                                }
                            }
                            elseif ($_.Name -eq 'host_info') {
                                $_.Value.psobject.properties | ForEach-Object {
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
                $Output | Export-Csv -Path $PSBoundParameters.Path -NoTypeInformation -Append -Force
            }
            else {
                Write-Error "CSV conversion is not available for this request type"
            }
        }
    }
}
function Find-Duplicate {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:FindDuplicate')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $PSBoundParameters.Help) {
            $Criteria = @('device_id', 'hostname', 'first_seen', 'last_seen')
            $InputFields = ($PSBoundParameters.Hosts | Get-Member -MemberType NoteProperty).Name
            function Group-Selection ($Selection, $Criteria) {
                ((($Selection | Group-Object $Criteria).Where({ $_.Count -gt 1 })).Group |
                Group-Object $Criteria).foreach{
                    $_.Group | Sort-Object last_seen | Select-Object -First (($_.Count) - 1)
                }
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            try {
                ($Criteria).foreach{
                    if ($InputFields -notcontains $_) {
                        throw "Input object does not contain '$_' field"
                    }
                }
                $Param = @{
                    Selection = $PSBoundParameters.Hosts | Select-Object $Criteria
                    Criteria = 'hostname'
                }
                $Duplicates = Group-Selection @Param
                if ($Duplicates) {
                    $Duplicates
                }
                else {
                    Write-Warning "No duplicates found"
                }
            }
            catch {
                $_
            }
        }
    }
}
function Get-Queue {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'script:GetQueue')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:GetQueue')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Days = if (-not $PSBoundParameters.Days) {
            7
        } else {
            $PSBoundParameters.Days
        }
        $FileDateTime = Get-Date -Format FileDateTime
        $OutputFile = "$pwd\FalconQueue_$FileDateTime.csv"
        $RequiresResponder = @('cp', 'encrypt', 'get', 'kill', 'map', 'memdump', 'mkdir', 'mv', 'reg delete',
            'reg load', 'reg set', 'reg unload', 'restart', 'rm', 'runscript', 'shutdown', 'umount', 'unmap',
            'xmemdump', 'zip')
        $RequiresAdmin = @('put', 'run')
        function Add-Field ($Object, $Name, $Value) {
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            try {
                $Param = @{
                    Filter  = ("(deleted_at:null+commands_queued:1),(created_at:>'Last $Days days'+" +
                        "commands_queued:1)")
                    All     = $true
                    Verbose = $true
                }
                Get-FalconSession @Param | ForEach-Object {
                    $Param = @{
                        Ids     = $_
                        Queue   = $true
                        Verbose = $true
                    }
                    Get-FalconSession @Param | ForEach-Object {
                        foreach ($Session in $_) {
                            $Session.Commands | ForEach-Object {
                                $Object = [PSCustomObject] @{
                                    aid                = $Session.aid
                                    user_id            = $Session.user_id
                                    user_uuid          = $Session.user_uuid
                                    session_id         = $Session.id
                                    session_created_at = $Session.created_at
                                    session_deleted_at = $Session.deleted_at
                                    session_updated_at = $Session.updated_at
                                    session_status     = $Session.status
                                    command_complete   = $false
                                    command_stdout     = $null
                                    command_stderr     = $null
                                }
                                $_.PSObject.Properties | ForEach-Object {
                                    $Name = if ($_.Name -match '(created_at|deleted_at|status|updated_at)') {
                                        "command_$($_.Name)"
                                    } else {
                                        $_.Name
                                    }
                                    $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $_.Value)))
                                }
                                if ($Object.command_status -eq 'FINISHED') {
                                    $Permission = if ($RequiresAdmin -contains $Object.base_command) {
                                        'Admin'
                                    } elseif ($RequiresResponder -contains $Object.base_command) {
                                        'Responder'
                                    } else {
                                        $null
                                    }
                                    $Param = @{
                                        CloudRequestId = $Object.cloud_request_id
                                        Verbose        = $true
                                        ErrorAction    = 'SilentlyContinue'
                                    }
                                    $CmdResult = & "Confirm-Falcon$($Permission)Command" @Param
                                    if ($CmdResult) {
                                        ($CmdResult | Select-Object stdout, stderr, complete).PSObject.Properties |
                                        ForEach-Object {
                                            $Object."command_$($_.Name)" = $_.Value
                                        }
                                    }
                                }
                                $Object | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                            }
                        }
                    }
                }
            } catch {
                $_
            } finally {
                if (Test-Path $OutputFile) {
                    Get-ChildItem $OutputFile | Out-Host
                }
            }
        }
    }
}
function Invoke-Deploy {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:InvokeDeploy')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Max = 500
        $FileDateTime = Get-Date -Format FileDateTime
        $OutputFile = "$pwd\FalconDeploy_$FileDateTime.csv"
        $FilePath = $Falcon.GetAbsolutePath($Dynamic.Path.Value)
        $Filename = "$([System.IO.Path]::GetFileName($FilePath))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($FilePath))"
        function Write-Result ($Object, $Step, $BatchId) {
            $Output = foreach ($Item in $Object) {
                [PSCustomObject] @{
                    aid = $Item.aid
                    batch_id = $BatchId
                    session_id = $null
                    cloud_request_id = $null
                    complete = $false
                    stdout = $null
                    stderr = $null
                    errors = $null
                    offline_queued = $false
                    deployment_step = $Step
                }
            }
            foreach ($Result in ($Object | Select-Object aid, session_id, task_id, complete, stdout,
            stderr, errors, offline_queued)) {
                $Result.PSObject.Properties | ForEach-Object {
                    $Value = if (($_.Name -eq 'errors') -and $_.Value) {
                        "$($_.Value.code): $($_.Value.message)"
                    }
                    else {
                        $_.Value
                    }
                    $Name = if ($_.Name -eq 'task_id') {
                        'cloud_request_id'
                    }
                    else {
                        $_.Name
                    }
                    $Output | Where-Object { $_.aid -eq $Result.aid } | ForEach-Object {
                        $_.$Name = $Value
                    }
                }
            }
            $Output | Export-Csv $OutputFile -Append -NoTypeInformation
        }
        if (-not $PSBoundParameters.Help -and $FilePath) {
            try {
                Write-Host "Checking cloud for existing file..."
                $CloudFile = foreach ($Item in (
                Get-FalconPutFile -Filter "name:['$Filename']" -Detailed | Select-Object id, name,
                created_timestamp, modified_timestamp, sha256)) {
                    [ordered] @{
                        id                 = $Item.id
                        name               = $Item.Name
                        created_timestamp  = [datetime] $Item.created_timestamp
                        modified_timestamp = [datetime] $Item.modified_timestamp
                        sha256             = $Item.sha256
                    }
                }
                if ($CloudFile) {
                    $LocalFile = foreach ($Item in (Get-ChildItem $FilePath |
                        Select-Object CreationTime, Name, LastWriteTime)) {
                        [ordered] @{
                            name               = $Item.Name
                            created_timestamp  = [datetime] $Item.CreationTime
                            modified_timestamp = [datetime] $Item.LastWriteTime
                            sha256             = ((Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash).ToLower()
                        }
                    }
                    if ($LocalFile.sha256 -eq $CloudFile.sha256) {
                        Write-Host "Matched hash values between local and cloud files..."
                    }
                    else {
                        foreach ($Item in @('CloudFile', 'LocalFile')) {
                            Write-Host "[$($Item -replace 'File', $null)]"
                            (Get-Variable $Item).Value | Select-Object name, created_timestamp,
                            modified_timestamp, sha256 | Format-List | Out-Host
                        }
                        $FileChoice = $host.UI.PromptForChoice(
                            "$Filename exists in your 'Put Files'. Use the existing version?", $null,
                            [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No"), 0)
                        if ($FileChoice -eq 0) {
                            Write-Host "Proceeding with $($CloudFile.id)..."
                        }
                        else {
                            $RemovePut = Remove-FalconPutFile -FileId $CloudFile.id
                            if ($RemovePut.resources_affected -eq 1) {
                                Write-Host "Removed cloud file $($CloudFile.id)"
                            }
                        }
                    }
                }
            }
            catch {
                $_
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif (-not $FilePath) {
            Write-Error "Cannot find path '$($Dynamic.Path.Value)' because it does not exist."
        }
        else {
            try {
                if (($RemovePut.resources_affected -eq 1) -or (-not $CloudFile)) {
                    Write-Host "Uploading $Filename..."
                    $Param = @{
                        Path        = $FilePath
                        Name        = $Filename
                        Description = "$ProcessName"
                        Comment     = "PSFalcon: Invoke-FalconDeploy"
                    }
                    $AddPut = Send-FalconPutFile @Param
                    if ($AddPut.resources_affected -ne 1) {
                        break
                    }
                }
                for ($i = 0; $i -lt $PSBoundParameters.HostIds.count; $i += $Max) {
                    $Param = @{
                        HostIds = $PSBoundParameters.HostIds[$i..($i + ($Max - 1))]
                    }
                    switch -Regex ($PSBoundParameters.Keys) {
                        '(QueueOffline|Timeout)' {
                            if ($PSBoundParameters.$_) {
                                $Param[$_] = $PSBoundParameters.$_
                            }
                        }
                    }
                    $Session = Start-FalconSession @Param
                    if ($Session) {
                        $Param = @{
                            Object = $Session.hosts
                            Step = 'session_start'
                            BatchId = $Session.batch_id
                        }
                        Write-Result @Param
                        $SessionHosts = ($Session.hosts | Where-Object { ($_.complete -eq $true) -or
                        ($_.offline_queued -eq $true) }).aid
                    }
                    if ($SessionHosts) {
                        Write-Host "Pushing $Filename to $($SessionHosts.count) host(s)..."
                        $Param = @{
                            BatchId         = $Session.batch_id
                            Command         = 'put'
                            Arguments       = "$Filename"
                            OptionalHostIds = $SessionHosts
                        }
                        if ($PSBoundParameters.Timeout) {
                            $Param['Timeout'] = $PSBoundParameters.Timeout
                        }
                        $CmdPut = Invoke-FalconAdminCommand @Param
                        if ($CmdPut) {
                            $Param = @{
                                Object = $CmdPut
                                Step = 'put_file'
                                BatchId = $Session.batch_id
                            }
                            Write-Result @Param
                            $PutHosts = ($CmdPut | Where-Object { ($_.stdout -eq
                            'Operation completed successfully.') -or ($_.offline_queued -eq $true) }).aid
                        }
                    }
                    if ($PutHosts) {
                        Write-Host "Starting $Filename on $($PutHosts.count) host(s)..."
                        $Arguments = "\$Filename"
                        if ($PSBoundParameters.Arguments) {
                            $Arguments += " -CommandLine=`"$($PSBoundParameters.Arguments)`""
                        }
                        $Param = @{
                            BatchId         = $Session.batch_id
                            Command         = 'run'
                            Arguments       = $Arguments
                            OptionalHostIds = $PutHosts
                        }
                        if ($PSBoundParameters.Timeout) {
                            $Param['Timeout'] = $PSBoundParameters.Timeout
                        }
                        $CmdRun = Invoke-FalconAdminCommand @Param
                        if ($CmdRun) {
                            $Param = @{
                                Object = $CmdRun
                                Step = 'run_file'
                                BatchId = $Session.batch_id
                            }
                            Write-Result @Param
                        }
                    }
                }
            }
            catch {
                $_
            }
            finally {
                if (Test-Path $OutputFile) {
                    Get-ChildItem $OutputFile | Out-Host
                }
            }
        }
    }
}
function Invoke-RTR {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:InvokeRTR')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not $PSBoundParameters.Help) {
            # Max number of hosts per session
            $MaxHosts = 500
            # Sleep time, and max time to sleep when interacting with a single host
            $Sleep = 2
            $MaxSleep = 30
            # Commands segregated by permission level
            $Responder = @("cp","encrypt","get","kill","map","memdump","mkdir","mv","reg delete","reg load",
                "reg set","reg unload","restart","rm","shutdown","umount","unmap","update history",
                "update install","update list","update install","xmemdump","zip")
            $Admin = @("put","run","runscript")
            # Determine permission level from input command
            $Permission = switch ($PSBoundParameters.Command) {
                { $Admin -contains $_ } { 'Admin' }
                { $Responder -contains $_ } { 'Responder' }
                default { $null }
            }
            # Force 'Timeout' into 'Arguments' when using 'runscript'
            if ($PSBoundParameters.Command -match 'runscript' -and $PSBoundParameters.Timeout -and
                ($PSBoundParameters.Arguments -notmatch "-Timeout=\d{2,3}")) {
                $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
                if ($HostCount -eq 1) {
                    $MaxSleep = $PSBoundParameters.Timeout
                }
            }
            $InvokeCmd = if ($PSBoundParameters.Command -eq 'get' -and $PSBoundParameters.HostIds.count -gt 1) {
                # Set command for 'get' with multiple hosts
                "Invoke-FalconBatchGet"
            }
            else {
                # Set command
                "Invoke-Falcon$($Permission)Command"
            }
            if ($PSBoundParameters.HostIds.count -eq 1) {
                # Set confirmation command to match
                $ConfirmCmd = "Confirm-Falcon$($Permission)Command"
            }
            function Write-Result ($Object) {
                $Object.PSObject.Properties | ForEach-Object {
                    $Value = if (($_.Value -is [object[]]) -and ($_.Value[0] -is [string])) {
                        # Convert array results into strings
                        $_.Value -join ', '
                    }
                    elseif ($_.Value.code -and $_.Value.message) {
                        # Convert error code and message into string
                        "$($_.Value.code): $($_.Value.message)"
                    }
                    else {
                        $_.Value
                    }
                    $Name = if ($_.Name -eq 'task_id') {
                        # Rename 'task_id'
                        'cloud_request_id'
                    }
                    elseif ($_.Name -eq 'queued_command_offline') {
                        # Rename 'queued_command_offline'
                        'offline_queued'
                    }
                    else {
                        $_.Name
                    }
                    $Item = if ($Object.aid) {
                        # Match using 'aid' for batches
                        $Output | Where-Object { $_.aid -eq $Object.aid }
                    }
                    else {
                        # Assume single host
                        $Output[0]
                    }
                    if ($Item.PSObject.Properties.Name -contains $Name) {
                        # Add result to output
                        $Item.$Name = $Value
                    }
                }
            }
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            for ($i = 0; $i -lt $PSBoundParameters.HostIds.count; $i += $MaxHosts) {
                try {
                    [array] $Output = ($PSBoundParameters.HostIds[$i..($i + ($MaxHosts - 1))]).foreach{
                        # Create base output object for each host
                        [PSCustomObject] @{
                            aid = $_
                            session_id = $null
                            cloud_request_id = $null
                            complete = $false
                            offline_queued = $false
                            stdout = $null
                            stderr = $null
                            errors = $null
                        }
                    }
                    # Determine total number of hosts and set request parameters
                    $HostParam = if ($Output.aid.count -eq 1) {
                        $Output[0].PSObject.Properties.Remove('batch_id')
                        'HostId'
                    }
                    else {
                        'HostIds'
                    }
                    $Param = @{
                        $HostParam = $Output.aid
                    }
                    switch ($PSBoundParameters.Keys) {
                        'QueueOffline' {
                            $Param['QueueOffline'] = $PSBoundParameters.$_
                        }
                        'Timeout' {
                            if ($HostParam -eq 'HostIds') {
                                $Param['Timeout'] = $PSBoundParameters.$_
                            }
                        }
                    }
                    # Start session and capture results
                    $Init = Start-FalconSession @Param
                    if ($Init) {
                        $Content = if ($Init.hosts) {
                            $Init.hosts
                        }
                        else {
                            $Init
                        }
                        $Content | ForEach-Object {
                            Write-Result -Object $_
                        }
                        if ($Init.batch_id) {
                            $Output | Where-Object { $_.session_id } | ForEach-Object {
                                # Add batch_id
                                $_.PSObject.Properties.Add(
                                    (New-Object PSNoteProperty('batch_id', $Init.batch_id)))
                            }
                        }
                        # Set command parameters based on init result
                        $SessionType = if ($HostParam -eq 'HostIds') {
                            'BatchId'
                            $IdValue = $Init.batch_id
                        }
                        else {
                            'SessionId'
                            $IdValue = $Init.session_id
                        }
                        $Param = @{
                            $SessionType = $IdValue
                        }
                        switch ($PSBoundParameters.Keys) {
                            # Add user input to command parameters
                            'Command' {
                                $Param[$_] = $PSBoundParameters.$_
                            }
                            'Arguments' {
                                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                                    $Param['Path'] = $PSBoundParameters.$_
                                }
                                else {
                                    $Param[$_] = $PSBoundParameters.$_
                                }
                            }
                            'Timeout' {
                                if ($SessionType -eq 'BatchId') {
                                    $Param[$_] = $PSBoundParameters.$_
                                }
                            }
                        }
                        # Perform command request
                        $Request = & $InvokeCmd @Param
                    }
                    if ($Request -and $HostParam -eq 'HostIds') {
                        # Capture results and output batch commands
                        $Request | ForEach-Object {
                            Write-Result -Object $_
                        }
                        $Output
                    }
                    elseif ($Request) {
                        # Capture results
                        Write-Result -Object $Request
                        if ($Output.cloud_request_id -and $Output.complete -eq $false -and
                        $Output.offline_queued -eq $false) {
                            do {
                                # Loop command confirmation using intervals of $Sleep
                                Start-Sleep -Seconds $Sleep
                                $Confirm = & $ConfirmCmd -CloudRequestId $Output.cloud_request_id
                                Write-Result -Object $Confirm
                                $i += $Sleep
                            } until (
                                # Break if command is complete or $MaxSleep is reached
                                ($Output[0].complete -eq $true) -or ($i -ge $MaxSleep)
                            )
                        }
                        # Output results
                        $Output
                    }
                }
                catch {
                    $_
                }
            }
        }
    }
}
function Open-Stream {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'script:OpenStream')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:OpenStream')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif (($PSVersionTable.PSVersion.Major -lt 6) -or ($IsWindows -eq $true)) {
            try {
                $Stream = Get-FalconStream -AppId 'psfalcon' -Format json
                if ($Stream) {
                    $ArgumentList =
                    "try {
                        `$Param = @{
                            Uri = '$($Stream.datafeedURL)'
                            Method = 'get'
                            Headers = @{
                                accept = 'application/json'
                                authorization = 'Token $($Stream.sessionToken.token)'
                            }
                            OutFile = '$($pwd)\Stream_$(Get-Date -Format FileDateTime).json'
                        }
                        Invoke-WebRequest @Param
                    } catch {
                        Write-Output `$_ | Out-File `$FilePath
                    }"
                    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList
                }
            }
            catch {
                $_
            }
        }
        else {
            throw "This command is only compatible with PowerShell on Windows"
        }
    }
}
function Search-MalQueryHash {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:MalQueryHash')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Sleep = 5
        $MaxSleep = 30
        $Search = 'Invoke-FalconMalQuery'
        $Confirm = 'Get-FalconMalQuery'
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            try {
                $Param = @{
                    YaraRule = "import `"hash`"`nrule SearchHash`n{`ncondition:`nhash.sha256(0, filesize) == " +
                    "`"$($PSBoundParameters.Sha256)`"`n}"
                    FilterMeta = 'sha256', 'type', 'label', 'family'
                }
                $Request = & $Search @Param
                if ($Request.reqid) {
                    $Param = @{
                        Ids = $Request.reqid
                        OutVariable = 'Result'
                    }
                    if ((& $Confirm @Param).status -EQ 'inprogress') {
                        do {
                            Start-Sleep -Seconds $Sleep
                            $i += $Sleep
                        } until (
                            ((& $Confirm @Param).status -NE 'inprogress') -or ($i -ge $MaxSleep)
                        )
                    }
                    $Result
                }
            }
            catch {
                $_
            }
        }
    }
}
function Show-Map {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:ShowMap')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $FalconUI = "$($Falcon.Hostname -replace 'api', 'falcon')"
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            $Param.Query = $Param.Query | ForEach-Object {
                $Split = $_ -split ':'
                $Type = switch ($Split[0]) {
                    'sha256' { 'hash' }
                    'md5' { 'hash' }
                    'ipv4' { 'ip' }
                    'ipv6' { 'ip' }
                    'domain' { 'domain' }
                }
                "$($Type):'$($Split[1])'"
            }
            Start-Process "$($FalconUI)$($Falcon.Endpoints($Endpoints[0]).path)$($Param.Query -join ',')"
        }
    }
}
function Show-Module {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'script:ShowModule')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:ShowModule')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Parent = Split-Path -Path $Falcon.GetAbsolutePath($PSScriptRoot) -Parent
            if (Test-Path "$Parent\PSFalcon.psd1") {
                $Module = Import-PowerShellDataFile $Parent\PSFalcon.psd1
                [PSCustomObject] @{
                    ModuleVersion = "v$($Module.ModuleVersion) {$($Module.GUID)}"
                    ModulePath = $Parent
                    UserHome = $HOME
                    UserPSModulePath = ($env:PSModulePath -split ';') -join ', '
                    UserSystem = ("PowerShell $($PSVersionTable.PSEdition): v$($PSVersionTable.PSVersion)" +
                        " [$($PSVersionTable.OS)]")
                } | Format-List
            }
            else {
                throw "PSFalcon.psd1 missing from default location"
            }
        }
    }
}
function Test-Token {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'script:TestToken')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:TestToken')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            [PSCustomObject] @{
                Token = if ($Falcon.Token -and ($Falcon.Expires -gt (Get-Date).AddSeconds(30))) {
                    $true
                } else {
                    $false
                }
                Hostname = $Falcon.Hostname
                ClientId = $Falcon.ClientId
                MemberCid = $Falcon.MemberCid
            }
        }
    }
}