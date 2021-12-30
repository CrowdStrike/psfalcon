function Get-FalconQueue {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [int] $Days,

        [Parameter(Position = 2)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','host_hidden_status','hostname','last_seen',
            'local_ip','mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
            'reduced_functionality_mode','serial_number','system_manufacturer','system_product_name','tags')]
        [array] $Include
    )
    begin {
        $Days = if ($PSBoundParameters.Days) {
            $PSBoundParameters.Days
        } else {
            7
        }
        # Properties to capture from request results
        $Properties = @{
            Session = @('aid', 'user_id', 'user_uuid', 'id', 'created_at', 'deleted_at', 'status')
            Command = @('stdout', 'stderr', 'complete')
        }
        # Define output path
        $OutputFile = Join-Path -Path (Get-Location).Path -ChildPath "FalconQueue_$(
            Get-Date -Format FileDateTime).csv"
    }
    process {
        try {
            $SessionParam = @{
                Filter   = "(deleted_at:null+commands_queued:1),(created_at:>'last $Days days'+commands_queued:1)"
                Detailed = $true
                All      = $true
                Verbose  = $true
            }
            $Sessions = Get-FalconSession @SessionParam | Select-Object id, device_id
            [array] $HostInfo = if ($PSBoundParameters.Include) {
                # Capture host information for eventual output
                Get-FalconHost -Ids ($Sessions.device_id | Group-Object).Name | Select-Object @(
                    $PSBoundParameters.Include + 'device_id')
            }
            foreach ($Session in (Get-FalconSession -Ids $Sessions.id -Queue -Verbose)) {
                @($Session.Commands).foreach{
                    # Create output for each individual command in queued session
                    $Item = [PSCustomObject] @{}
                    @($Session | Select-Object $Properties.Session).foreach{
                        @($_.PSObject.Properties).foreach{
                            # Add session properties with 'session' prefix
                            $Name = if ($_.Name -match '^(id|(created|deleted|updated)_at|status)$') {
                                "session_$($_.Name)"
                            } else {
                                $_.Name
                            }
                            Add-Property -Object $Item -Name $Name -Value $_.Value
                        }
                    }
                    @($_.PSObject.Properties).foreach{
                        # Add command properties
                        $Name = if ($_.Name -match '^((created|deleted|updated)_at|status)$') {
                            "command_$($_.Name)"
                        } else {
                            $_.Name
                        }
                        Add-Property -Object $Item -Name $Name -Value $_.Value
                    }
                    if ($Item.command_status -eq 'FINISHED') {
                        # Update command properties with results
                        $Param = @{
                            CloudRequestId = $Item.cloud_request_id
                            Verbose        = $true
                            ErrorAction    = 'SilentlyContinue'
                        }
                        $ConfirmCmd = Get-RtrCommand $Item.base_command -ConfirmCommand
                        @(& $ConfirmCmd @Param | Select-Object $Properties.Command).foreach{
                            @($_.PSObject.Properties).foreach{
                                Add-Property -Object $Item -Name "command_$($_.Name)" -Value $_.Value
                            }
                        }
                    } else {
                        @('command_complete', 'command_stdout', 'command_stderr').foreach{
                            # Add empty command output
                            $Value = if ($_ -eq 'command_complete') {
                                $false
                            } else {
                                $null
                            }
                            Add-Property -Object $Item -Name $_ -Value $Value
                        }
                    }
                    if ($PSBoundParameters.Include -and $HostInfo) {
                        @($HostInfo.Where({ $_.device_id -eq $Item.aid })).foreach{
                            @($_.PSObject.Properties.Where({ $_.Name -ne 'device_id' })).foreach{
                                # Add 'Include' properties
                                Add-Property -Object $Item -Name $_.Name -Value $_.Value
                            }
                        }
                    }
                    # Export using 'Export-FalconReport' and suppress 'Get-ChildItem' output
                    [void] ($Item | Export-FalconReport $OutputFile)
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
                for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 1000) {
                    $Param = @{
                        HostIds = ($HostArray[$i..($i + 999)]).device_id
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
    [CmdletBinding(DefaultParameterSetName = 'HostId')]
    param(
        [Parameter(ParameterSetName = 'HostId', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true, Position = 1)]
        [ValidateSet('cat', 'cd', 'clear', 'cp', 'csrutil', 'encrypt', 'env', 'eventlog', 'filehash', 'get',
            'getsid', 'history', 'ifconfig', 'ipconfig', 'kill', 'ls', 'map', 'memdump', 'mkdir', 'mount', 'mv',
            'netstat', 'ps', 'put', 'put-and-run', 'reg delete', 'reg load', 'reg query', 'reg set', 'reg unload',
            'restart', 'rm', 'run', 'runscript', 'shutdown', 'umount', 'unmap', 'update history',
            'update install', 'update list', 'users', 'xmemdump', 'zip')]
        [string] $Command,

        [Parameter(ParameterSetName = 'HostId', Position = 2)]
        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [Parameter(ParameterSetName = 'GroupId', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [Parameter(ParameterSetName = 'GroupId', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostId')]
        [Parameter(ParameterSetName = 'HostIds')]
        [Parameter(ParameterSetName = 'GroupId')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostId', ValueFromPipeline = $true, Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $HostId,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds,

        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        if ($PSCmdlet.ParameterSetName -ne 'HostId') {
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
    }
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'HostId') {
                $InitParam = @{
                    HostId = $PSBoundParameters.HostId
                }
                switch ($PSBoundParameters.Keys) {
                    'QueueOffline' { $InitParam[$_] = $PSBoundParameters.$_ }
                }
                $Init = Start-FalconSession @InitParam
                $Request = if ($Init.session_id) {
                    $CmdParam = @{
                        # Send 'runscript' with tag values
                        SessionId = $Init.session_id
                    }
                    switch -Regex ($PSBoundParameters.Keys) {
                        '^(Command|Arguments)$' { $CmdParam[$_] = $PSBoundParameters.$_ }
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
                    $Confirm | ForEach-Object {
                        $CmdId = if ($_.task_id -and !$_.cloud_request_id) {
                            # Rename 'task_id' to 'cloud_request_id'
                            Add-Property -Object $_ -Name 'cloud_request_id' -Value $_.task_id
                            $_.PSObject.Properties.Remove('task_id')
                            'cloud_request_id'
                        } else {
                            'task_id'
                        }
                        $_ | Select-Object session_id, $CmdId, complete, stdout, stderr
                    }
                } else {
                    $Request
                }
            } else {
                [array] $HostArray = if ($PSCmdlet.ParameterSetName -eq 'GroupId') {
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
                for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 1000) {
                    # Create baseline output and define request parameters
                    [array] $Group = Initialize-Output $HostArray[$i..($i + 999)]
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
            }
        } catch {
            throw $_
        }
    }
}
function Invoke-FalconScript {
<#
.SYNOPSIS
Execute a Real-time Response Library script
.DESCRIPTION
Requires 'real-time-response-admin:write'.

The selected script must match one in the Real-time Response Library (https://github.com/bk-cs/rtr) without a
file extension.
.PARAMETER Name
Script name, not including file extension
.PARAMETER Arguments
Arguments to include with 'runscript'
.PARAMETER Timeout
Length of time to wait for a result, in seconds
.PARAMETER QueueOffline
Add non-responsive Hosts to the offline queue
.PARAMETER HostId
Host identifier
.PARAMETER HostIds
Host identifier(s)
.EXAMPLE
PS>Invoke-FalconScript -Name list_sensor_tags -HostIds <id>, <id>

List the FalconSensorTag values for hosts <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = 'HostId')]
    param(
        [Parameter(ParameterSetName = 'HostId', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = 'HostId', Position = 2)]
        [Parameter(ParameterSetName = 'HostIds', Position = 2)]
        [string] $Arguments,

        [Parameter(ParameterSetName = 'HostIds', Position = 3)]
        [ValidateRange(30,600)]
        [int] $Timeout,

        [Parameter(ParameterSetName = 'HostId')]
        [Parameter(ParameterSetName = 'HostIds')]
        [boolean] $QueueOffline,

        [Parameter(ParameterSetName = 'HostId', Mandatory = $true, ValueFromPipeline = $true)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id')]
        [string] $HostId,

        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $HostIds
    )
    begin {
        if ($PSBoundParameters.Timeout -and $PSBoundParameters.Arguments -notmatch '-Timeout=\d+') {
            $PSBoundParameters.Arguments += " -Timeout=$($PSBoundParameters.Timeout)"
        }
    }
    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'HostId') {
                $HostInfo = Get-FalconHost -Ids $PSBoundParameters.HostId |
                    Select-Object cid, device_id, platform_name
                if ($HostInfo.platform_name) {
                    $RawScript = Get-LibraryScript -Name $PSBoundParameters.Name -Platform $HostInfo.platform_name
                    if ($RawScript) {
                        $InvokeParam = @{
                            HostId    = $HostInfo.device_id
                            Command   = 'runscript'
                            Arguments = '-Raw=```' + $RawScript + '```'
                        }
                        if ($PSBoundParameters.Arguments) {
                            $InvokeParam.Arguments += " $($PSBoundParameters.Arguments)"
                        }
                        if ($PSBoundParameters.QueueOffline) {
                            $InvokeParam['QueueOffline'] = $PSBoundParameters.QueueOffline
                        }
                        foreach ($Result in (Invoke-FalconRtr @InvokeParam)) {
                            if ($Result.stdout) {
                                $Result.stdout = try {
                                    $Result.stdout -split '\n' | ForEach-Object {
                                        $_ | ConvertFrom-Json
                                    }
                                } catch {
                                    $Result.stdout
                                }
                            }
                            $Result
                        }
                    } else {
                        throw "No script matching '$($PSBoundParameters.Name)' for $($HostInfo.platform_name)."
                    }
                } else {
                    throw "No host found matching '$($PSBoundParameters.Id)'."
                }
            } else {
                $HostInfo = Get-FalconHost -Ids $PSBoundParameters.HostIds |
                    Select-Object cid, device_id, platform_name
                foreach ($Platform in ($HostInfo.platform_name | Group-Object).Name) {
                    $RawScript = Get-LibraryScript -Name $PSBoundParameters.Name -Platform $Platform
                    if ($RawScript) {
                        $InvokeParam = @{
                            Command   = 'runscript'
                            Arguments =  '-Raw=```' + $RawScript + '```'
                            HostIds   = ($HostInfo | Where-Object { $_.platform_name -eq $Platform }).device_id
                        }
                        if ($PSBoundParameters.Arguments) {
                            $InvokeParam.Arguments += " $($PSBoundParameters.Arguments)"
                        }
                        @('Timeout','QueueOffline').foreach{
                            if ($PSBoundParameters.Keys -contains $_) {
                                $InvokeParam[$_] = $PSBoundParameters.$_
                            }
                        }
                        foreach ($Result in (Invoke-FalconRtr @InvokeParam)) {
                            if ($Result.stdout) {
                                $Result.stdout = try {
                                    $Result.stdout -split '\n' | ForEach-Object {
                                        $_ | ConvertFrom-Json
                                    }
                                } catch {
                                    $Result.stdout
                                }
                            }
                            $Result
                        }
                    } else {
                        Write-Error "No script matching '$($PSBoundParameters.Name)' for $Platform."
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}