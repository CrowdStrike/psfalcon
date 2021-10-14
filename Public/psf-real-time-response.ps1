function Get-FalconQueue {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [int] $Days,

        [Parameter(Position = 2)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','host_hidden_status','hostname','last_seen',
            'local_ip','mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
            'provision_status','reduced_functionality_mode','serial_number','system_manufacturer',
            'system_product_name','tags')]
        [array] $Include
    )
    begin {
        $Days = if ($PSBoundParameters.Days) {
            $PSBoundParameters.Days
        } else {
            7
        }
        $OutputFile = Join-Path -Path (Get-Location).Path -ChildPath "FalconQueue_$(
            Get-Date -Format FileDateTime).csv"
        $Filter = "(deleted_at:null+commands_queued:1),(created_at:>'last $Days days'+commands_queued:1)"
    }
    process {
        try {
            $Sessions = Get-FalconSession -Filter $Filter -Detailed -All -Verbose | Select-Object id, device_id
            if ($PSBoundParameters.Include) {
                $HostTable = @{}
                $PSBoundParameters.Include += 'device_id'
                @(Get-FalconHost -Ids ($Sessions.device_id | Group-Object).Name -Verbose |
                Select-Object $PSBoundParameters.Include).foreach{
                    $HostTable[$_.device_id] = $_ | Select-Object -ExcludeProperty device_id
                }
            }
            foreach ($Session in (Get-FalconSession -Ids $Sessions.id -Queue -Verbose)) {
                @($Session.Commands).foreach{
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
                    @($_.PSObject.Properties).foreach{
                        $Name = if ($_.Name -match '^(created_at|deleted_at|status|updated_at)$') {
                            "command_$($_.Name)"
                        } else {
                            $_.Name
                        }
                        $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $_.Value)))
                    }
                    if ($Object.command_status -eq 'FINISHED') {
                        $ConfirmCmd = Get-RtrCommand $Object.base_command -ConfirmCommand
                        $Param = @{
                            CloudRequestId = $Object.cloud_request_id
                            Verbose        = $true
                            ErrorAction    = 'SilentlyContinue'
                        }
                        $CmdResult = & $ConfirmCmd @Param
                        if ($CmdResult) {
                            (($CmdResult | Select-Object stdout, stderr, complete).PSObject.Properties).foreach{
                                $Object."command_$($_.Name)" = $_.Value
                            }
                        }
                    }
                    if ($PSBoundParameters.Include) {
                        @(($HostTable.($Session.aid)).PSObject.Properties.Where({ $_.MemberType -eq
                        'NoteProperty' -and $_.Name -ne 'device_id' })).foreach{
                            Add-Property -Object $Object -Name $_.Name -Value $_.Value
                        }
                    }
                    $Object | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                }
            }
        } catch {
            throw $_
        } finally {
            if (Test-Path $OutputFile) {
                Get-ChildItem $OutputFile
            }
        }
    }
}
function Invoke-FalconDeploy {
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName = 'HostIds')]
    param(
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true, Position = 1)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [Parameter(ParameterSetName = 'GroupId', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [Parameter(ParameterSetName = 'GroupId', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostIds')]
        [Parameter(ParameterSetName = 'GroupId')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds,

        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        # Fields to collect from 'Put' files list
        $PutFields = @('id', 'name', 'created_timestamp', 'modified_timestamp', 'sha256')
        function Write-RtrResult ($Object, $Step, $BatchId) {
            # Create output, append results and output to CSV
            $Output = foreach ($Item in $Object) {
                [PSCustomObject] @{
                    aid              = $Item.aid
                    batch_id         = $BatchId
                    session_id       = $null
                    cloud_request_id = $null
                    deployment_step  = $Step
                    complete         = $false
                    offline_queued   = $false
                    errors           = $null
                    stderr           = $null
                    stdout           = $null
                }
            }
            Get-RtrResult -Object $Object -Output $Output | Export-Csv $OutputFile -Append -NoTypeInformation
        }
        # Set output file and executable details
        $OutputFile = Join-Path -Path (Get-Location).Path -ChildPath "FalconDeploy_$(
            Get-Date -Format FileDateTime).csv"
        $FilePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        $Filename = "$([System.IO.Path]::GetFileName($FilePath))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($FilePath))"
        [array] $HostArray = if ($PSBoundParameters.GroupId) {
            if ((Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -Total) -gt 10000) {
                # Stop if number of members exceeds API limit
                throw "Group size exceeds maximum number of results [10,000]"
            } else {
                # Find Host Group member identifiers
                ,(Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -Detailed -All |
                    Select-Object device_id, platform_name)
            }
        } else {
            # Use provided Host identifiers
            ,(Get-FalconHost -Ids $PSBoundParameters.HostIds | Select-Object device_id, platform_name)
        }
        if ($HostArray) {
            try {
                Write-Host "Checking cloud for existing file..."
                $CloudFile = @(Get-FalconPutFile -Filter "name:['$Filename']" -Detailed |
                Select-Object $PutFields).foreach{
                    [PSCustomObject] @{
                        id                 = $_.id
                        name               = $_.name
                        created_timestamp  = [datetime] $_.created_timestamp
                        modified_timestamp = [datetime] $_.modified_timestamp
                        sha256             = $_.sha256
                    }
                }
                $LocalFile = @(Get-ChildItem $FilePath | Select-Object CreationTime, Name, LastWriteTime).foreach{
                    [PSCustomObject] @{
                        name               = $_.Name
                        created_timestamp  = $_.CreationTime
                        modified_timestamp = $_.LastWriteTime
                        sha256             = ((Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash).ToLower()
                    }
                }
                if ($LocalFile -and $CloudFile) {
                    if ($LocalFile.sha256 -eq $CloudFile.sha256) {
                        Write-Host "Matched hash values between local and cloud files..."
                    } else {
                        Write-Host "[CloudFile]"
                        $CloudFile | Select-Object name, created_timestamp, modified_timestamp, sha256 |
                            Format-List | Out-Host
                        Write-Host "[LocalFile]"
                        $LocalFile | Select-Object name, created_timestamp, modified_timestamp, sha256 |
                            Format-List | Out-Host
                        $FileChoice = $host.UI.PromptForChoice(
                            "'$Filename' exists in your 'Put' Files. Use existing version?", $null,
                            [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No"), 0)
                        if ($FileChoice -eq 0) {
                            Write-Host "Proceeding with CloudFile: $($CloudFile.id)..."
                        } else {
                            $RemovePut = Remove-FalconPutFile -Id $CloudFile.id
                            if ($RemovePut.writes.resources_affected -eq 1) {
                                Write-Host "Removed CloudFile: $($CloudFile.id)"
                            }
                        }
                    }
                }
            } catch {
                throw $_
            }
        }
    }
    process {
        if ($HostArray) {
            $AddPut = if ($RemovePut.writes.resources_affected -eq 1 -or !$CloudFile) {
                Write-Host "Uploading $Filename..."
                $Param = @{
                    Path        = $FilePath
                    Name        = $Filename
                    Description = "$ProcessName"
                    Comment     = 'PSFalcon: Invoke-FalconDeploy'
                }
                Send-FalconPutFile @Param
            }
            if ($AddPut.writes.resources_affected -ne 1 -and !$CloudFile.id) {
                throw "Upload failed."
            }
            try {
                for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 500) {
                    $Param = @{
                        HostIds = ($HostArray[$i..($i + 499)]).device_id
                    }
                    switch -Regex ($PSBoundParameters.Keys) {
                        '(QueueOffline|Timeout)' { $Param[$_] = $PSBoundParameters.$_ }
                    }
                    $Session = Start-FalconSession @Param
                    $SessionHosts = if ($Session.batch_id) {
                        # Output result to CSV and return list of successful 'session_start' hosts
                        Write-RtrResult -Object $Session.hosts -Step 'session_start' -BatchId $Session.batch_id
                        ($Session.hosts | Where-Object { $_.complete -eq $true -or
                            $_.offline_queued -eq $true }).aid
                    }
                    if ($SessionHosts) {
                        # Change to a 'temp' directory for each device, by platform
                        Write-Host "Initiated session with $(($SessionHosts | Measure-Object).Count) host(s)..."
                        foreach ($Pair in (@{
                            Windows = ($HostArray | Where-Object { $SessionHosts -contains $_.device_id -and
                                $_.platform_name -eq 'Windows' }).device_id
                            Mac     = ($HostArray | Where-Object { $SessionHosts -contains $_.device_id -and
                                $_.platform_name -eq 'Mac' }).device_id
                            Linux   = ($HostArray | Where-Object { $SessionHosts -contains $_.device_id -and
                                $_.platform_name -eq 'Linux' }).device_id
                        }).GetEnumerator().Where({ $_.Value })) {
                            $Param = @{
                                BatchId         = $Session.batch_id
                                Command         = 'cd'
                                OptionalHostIds = $Pair.Value
                            }
                            if ($PSBoundParameters.Timeout) {
                                $Param['Timeout'] = $PSBoundParameters.Timeout
                            }
                            $TempDir = switch ($Pair.Key) {
                                'Windows' { '\Windows\Temp' }
                                'Mac'     { '/tmp' }
                                'Linux'   { '/tmp' }
                            }
                            $Param['Arguments'] = $TempDir
                            $CmdCd = Invoke-FalconAdminCommand @Param
                            $CdHosts = if ($CmdCd) {
                                # Output result to CSV and return list of successful 'cd_temp' hosts
                                Write-RtrResult -Object $CmdCd -Step 'cd_temp' -BatchId $Session.batch_id
                                ,($CmdCd | Where-Object { ($_.complete -eq $true -and !$_.stderr) -or
                                    $_.offline_queued -eq $true }).aid
                            }
                            $PutHosts = if ($CdHosts) {
                                # Invoke 'put' on successful hosts
                                Write-Host ("Sending $Filename to $(($CdHosts | Measure-Object).Count)" +
                                    " $($Pair.Key) host(s)...")
                                $Param = @{
                                    BatchId         = $Session.batch_id
                                    Command         = 'put'
                                    Arguments       = $Filename
                                    OptionalHostIds = $CdHosts
                                }
                                if ($PSBoundParameters.Timeout) {
                                    $Param['Timeout'] = $PSBoundParameters.Timeout
                                }
                                $CmdPut = Invoke-FalconAdminCommand @Param
                                if ($CmdPut) {
                                    # Output result to CSV and return list of successful 'put_file' hosts
                                    Write-RtrResult -Object $CmdPut -Step 'put_file' -BatchId $Session.batch_id
                                    ($CmdPut | Where-Object { ($_.complete -eq $true -and !$_.stderr) -or
                                        $_.offline_queued -eq $true }).aid
                                }
                            }
                            if ($PutHosts -and $Pair.Key -eq 'Linux') {
                                # Modify 'put' file if running on Linux
                                Write-Host ("Modifying $Filename on $(($PutHosts | Measure-Object).Count)" +
                                    " $($Pair.Key) host(s)...")
                                $ModParam = @{
                                    BatchId         = $Session.batch_id
                                    Command         = 'runscript'
                                    Arguments       = '-Raw=```chmod +x ' + "$($TempDir)/$($Filename)" + '```'
                                    OptionalHostIds = $PutHosts
                                }
                                $CmdMod = Invoke-FalconAdminCommand @ModParam
                                $PutHosts = if ($CmdMod) {
                                    # Output result to CSV and return list of successful 'mod_file' hosts
                                    Write-RtrResult -Object $CmdMod -Step 'mod_file' -BatchId $Session.batch_id
                                    ($CmdMod | Where-Object { ($_.complete -eq $true -and !$_.stderr) -or
                                        $_.offline_queued -eq $true }).aid
                                }
                            }
                            if ($PutHosts) {
                                # Invoke 'run'
                                Write-Host ("Starting $Filename on $(($PutHosts | Measure-Object).Count)" +
                                    " $($Pair.Key) host(s)...")
                                $Arguments = if ($Pair.Key -eq 'Windows') {
                                    "$($TempDir)\$($Filename)"
                                } else {
                                    "$($TempDir)/$($Filename)"
                                }
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
                                    # Output result to CSV
                                    Write-RtrResult -Object $CmdRun -Step 'run_file' -BatchId $Session.batch_id
                                }
                            }
                        }
                    }
                }
            } catch {
                throw $_
            } finally {
                if (Test-Path $OutputFile) {
                    Get-ChildItem $OutputFile
                }
            }
        }
    }
}
function Invoke-FalconRtr {
    [CmdletBinding(DefaultParameterSetName = 'HostIds')]
    param(
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true, Position = 1)]
        [ValidateSet('cat', 'cd', 'clear', 'cp', 'csrutil', 'encrypt', 'env', 'eventlog', 'filehash', 'get',
            'getsid', 'history', 'ifconfig', 'ipconfig', 'kill', 'ls', 'map', 'memdump', 'mkdir', 'mount', 'mv',
            'netstat', 'ps', 'put', 'reg delete', 'reg load', 'reg query', 'reg set', 'reg unload', 'restart',
            'rm', 'run', 'runscript', 'shutdown', 'umount', 'unmap', 'update history', 'update install',
            'update list', 'users', 'xmemdump', 'zip')]
        [string] $Command,

        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [Parameter(ParameterSetName = 'GroupId', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [Parameter(ParameterSetName = 'GroupId', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostIds')]
        [Parameter(ParameterSetName = 'GroupId')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds,

        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        function Initialize-Output ([array] $HostIds) {
            # Create initial array of output for each host
            ($HostIds).foreach{
                $Item = [PSCustomObject] @{
                    aid              = $_
                    batch_id         = $null
                    session_id       = $null
                    cloud_request_id = $null
                    complete         = $false
                    offline_queued   = $false
                    errors           = $null
                    stderr           = $null
                    stdout           = $null
                }
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    Add-Property -Object $Item -Name 'batch_get_cmd_req_id' -Value $null
                }
                if ($PSBoundParameters.GroupId) {
                    Add-Property -Object $Item -Name 'host_group_id' -Value $PSBoundParameters.GroupId
                }
                $Item
            }
        }
        if ($PSBoundParameters.Timeout -and $PSBoundParameters.Command -eq 'runscript' -and
        $PSBoundParameters.Arguments -notmatch '-Timeout=\d{2,3}') {
            # Force 'Timeout' into 'Arguments' when using 'runscript'
            $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
        }
        # Determine Real-time Response command to invoke
        $InvokeCmd = if ($PSBoundParameters.Command -eq 'get') {
            'Invoke-FalconBatchGet'
        } else {
            Get-RtrCommand $PSBoundParameters.Command
        }
    }
    process {
        try {
            [array] $HostArray = if ($PSBoundParameters.GroupId) {
                if ((Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -Total) -gt 10000) {
                    # Stop if number of members exceeds API limit
                    throw "Group size exceeds maximum number of results [10,000]"
                } else {
                    # Find Host Group member identifiers
                    ,(Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -All)
                }
            } else {
                # Use provided Host identifiers
                ,$PSBoundParameters.HostIds
            }
            for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 500) {
                # Create baseline output and define request parameters
                [array] $Group = Initialize-Output $HostArray[$i..($i + 499)]
                $InitParam = @{
                    HostIds      = $Group.aid
                    QueueOffline = if ($PSBoundParameters.QueueOffline) {
                        $true
                    } else {
                        $false
                    }
                }
                # Define command request parameters
                if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                    $CmdParam = @{
                        FilePath = $PSBoundParameters.Arguments
                    }
                } else {
                    $CmdParam = @{
                        Command = $PSBoundParameters.Command
                    }
                    if ($PSBoundParameters.Arguments) {
                        $CmdParam['Arguments'] = $PSBoundParameters.Arguments
                    }
                }
                if ($PSBoundParameters.Timeout) {
                    @($InitParam, $CmdParam).foreach{
                        $_['Timeout'] = $PSBoundParameters.Timeout
                    }
                }
                # Start session
                $InitRequest = Start-FalconSession @InitParam
                if ($InitRequest.batch_id) {
                    # Capture session initialization result
                    $InitResult = Get-RtrResult -Object $InitRequest.hosts -Output $Group
                    @($InitResult | Where-Object { $_.session_id }).foreach{
                        # Add batch_id and clear 'stdout'
                        $_.batch_id = $InitRequest.batch_id
                        $_.stdout = $null
                    }
                    # Perform command request
                    $CmdRequest = & $InvokeCmd @CmdParam -BatchId $InitRequest.batch_id
                    if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                        # Capture 'hosts' for 'Invoke-FalconBatchGet'
                        $CmdContent = Get-RtrResult -Object $CmdRequest.hosts -Output $InitResult
                        @($CmdContent | Where-Object { $_.session_id -and $_.complete -eq $true }).foreach{
                            # Add 'batch_get_cmd_req_id' to output
                            Add-Property -Object $_ -Name 'batch_get_cmd_req_id' -Value (
                                $CmdRequest.batch_get_cmd_req_id)
                        }
                        $CmdContent
                    } else {
                        # Output result
                        Get-RtrResult -Object $CmdRequest -Output $InitResult
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}