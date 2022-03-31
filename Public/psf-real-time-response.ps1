function Get-FalconQueue {
<#
.SYNOPSIS
Create a report of Real-time Response commands in the offline queue
.DESCRIPTION
Requires 'real-time-response:read','real-time-response:write' and 'real-time-response-admin:write'.

Creates a CSV of pending Real-time Response commands and their related session information. Sessions within
the offline queue expire 7 days after creation by default. Sessions can have additional commands appended to
them to extend their expiration time.

Additional host information can be appended to the results using the 'Include' parameter.
.PARAMETER Days
Days worth of results to retrieve [default: 7]
.PARAMETER Include
Include additional properties
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=1)]
        [int32]$Days,

        [Parameter(Position=2)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','host_hidden_status','hostname',
            'last_seen','local_ip','mac_address','os_build','os_version','platform_name','product_type',
            'product_type_desc','reduced_functionality_mode','serial_number','system_manufacturer',
            'system_product_name','tags',IgnoreCase=$false)]
        [string[]]$Include
    )
    begin {
        $Days = if ($PSBoundParameters.Days) { $PSBoundParameters.Days } else { 7 }
        # Properties to capture from request results
        $Select = @{
            Session = @('aid','user_id','user_uuid','id','created_at','deleted_at','status')
            Command = @('stdout','stderr','complete')
        }
        # Define output path
        $OutputFile = Join-Path (Get-Location).Path "FalconQueue_$(Get-Date -Format FileDateTime).csv"
    }
    process {
        try {
            $SessionParam = @{
                Filter = "(deleted_at:null+commands_queued:1),(created_at:>'last $Days days'+commands_queued:1)"
                Detailed = $true
                All = $true
                Verbose = $true
            }
            $Sessions = Get-FalconSession @SessionParam | Select-Object id,device_id
            if (-not $Sessions) { throw "No queued Real-time Response sessions available." }
            [array]$HostInfo = if ($PSBoundParameters.Include) {
                # Capture host information for eventual output
                $Sessions.device_id | Get-FalconHost | Select-Object @($PSBoundParameters.Include + 'device_id')
            }
            foreach ($Session in ($Sessions.id | Get-FalconSession -Queue -Verbose)) {
                @($Session.Commands).foreach{
                    # Create output for each individual command in queued session
                    $Obj = [PSCustomObject] @{}
                    @($Session | Select-Object $Select.Session).foreach{
                        @($_.PSObject.Properties).foreach{
                            # Add session properties with 'session' prefix
                            $Name = if ($_.Name -match '^(id|(created|deleted|updated)_at|status)$') {
                                "session_$($_.Name)"
                            } else {
                                $_.Name
                            }
                            Add-Property $Obj $Name $_.Value
                        }
                    }
                    @($_.PSObject.Properties).foreach{
                        # Add command properties
                        $Name = if ($_.Name -match '^((created|deleted|updated)_at|status)$') {
                            "command_$($_.Name)"
                        } else {
                            $_.Name
                        }
                        Add-Property $Obj $Name $_.Value
                    }
                    if ($Obj.command_status -eq 'FINISHED') {
                        # Update command properties with results
                        $ConfirmCmd = Get-RtrCommand $Obj.base_command -ConfirmCommand
                        @($Obj.cloud_request_id | & $ConfirmCmd -Verbose -EA 4 |
                        Select-Object $Select.Command).foreach{
                            @($_.PSObject.Properties).foreach{ Add-Property $Obj "command_$($_.Name)" $_.Value }
                        }
                    } else {
                        @('command_complete','command_stdout','command_stderr').foreach{
                            # Add empty command output
                            $Value = if ($_ -eq 'command_complete') { $false } else { $null }
                            Add-Property $Obj $_ $Value
                        }
                    }
                    if ($PSBoundParameters.Include -and $HostInfo) {
                        @($HostInfo.Where({ $_.device_id -eq $Obj.aid })).foreach{
                            @($_.PSObject.Properties.Where({ $_.Name -ne 'device_id' })).foreach{
                                # Add 'Include' properties
                                Add-Property $Obj $_.Name $_.Value
                            }
                        }
                    }
                    $Obj | Export-Csv $OutputFile -NoTypeInformation -Append
                }
            }
        } catch {
            throw $_
        } finally {
            if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
        }
    }
}
function Invoke-FalconDeploy {
<#
.SYNOPSIS
Deploy and run an executable using Real-time Response
.DESCRIPTION
Requires 'devices:read','real-time-response-admin:write'.

'Put' files will be checked for identical file names,and if any are found,the Sha256 hash values will be
compared between your local and cloud files. If they are different,a prompt will appear asking which file to use.

If the file is not present in 'Put' files,it will be uploaded.

Once uploaded,a Real-time Response session will be started for the designated Host,'cd' will be used to
navigate to a temporary folder (\Windows\Temp or /tmp),then the file will be 'put' into that folder,and 'run'
if successfully transferred. If the file already exists,it will not be executed.

Details of each step will be output to a CSV file in the current directory.
.PARAMETER Path
Path to local file
.PARAMETER Argument
Arguments to include when running the executable
.PARAMETER Timeout
Length of time to wait for a result, in seconds
.PARAMETER QueueOffline
Add non-responsive Hosts to the offline queue
.PARAMETER HostId
Host identifier
.PARAMETER GroupId
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName='HostIds')]
    param(
        [Parameter(ParameterSetName='HostIds',Mandatory,Position=1)]
        [Parameter(ParameterSetName='GroupId',Mandatory,Position=1)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
            }
        })]
        [string]$Path,

        [Parameter(ParameterSetName='HostIds',Position=2)]
        [Parameter(ParameterSetName='GroupId',Position=2)]
        [Alias('Arguments')]
        [string]$Argument,

        [Parameter(ParameterSetName='HostIds',Position=3)]
        [Parameter(ParameterSetName='GroupId',Position=3)]
        [ValidateRange(30,600)]
        [int32]$Timeout,

        [Parameter(ParameterSetName='HostIds')]
        [Parameter(ParameterSetName='GroupId')]
        [boolean]$QueueOffline,

        [Parameter(ParameterSetName='HostIds',Mandatory)]
        [ValidatePattern('^\w{32}$')]
        [Alias('HostIds')]
        [string[]]$HostId,

        [Parameter(ParameterSetName='GroupId',Mandatory)]
        [ValidatePattern('^\w{32}$')]
        [string]$GroupId
    )
    begin {
        # Fields to collect from 'Put' files list
        $PutFields = @('id','name','created_timestamp','modified_timestamp','sha256')
        function Write-RtrResult ($Object,$Step,$BatchId) {
            # Create output, append results and output to CSV
            $Output = foreach ($Item in $Object) {
                [PSCustomObject] @{
                    aid = $Item.aid
                    batch_id = $BatchId
                    session_id = $null
                    cloud_request_id = $null
                    deployment_step = $Step
                    complete = $false
                    offline_queued = $false
                    errors = $null
                    stderr = $null
                    stdout = $null
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
        [array]$HostArray = if ($PSBoundParameters.GroupId) {
            if ((Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -Total) -gt 10000) {
                # Stop if number of members exceeds API limit
                throw "Group size exceeds maximum number of results [10,000]"
            } else {
                # Find Host Group member identifiers
                ,(Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId -Detailed -All |
                    Select-Object device_id,platform_name)
            }
        } else {
            # Use provided Host identifiers
            ,(Get-FalconHost -Id $PSBoundParameters.HostId | Select-Object device_id,platform_name)
        }
        if ($HostArray) {
            try {
                Write-Host "Checking cloud for existing file..."
                $CloudFile = @(Get-FalconPutFile -Filter "name:['$Filename']" -Detailed |
                Select-Object $PutFields).foreach{
                    [PSCustomObject] @{
                        id = $_.id
                        name = $_.name
                        created_timestamp = [datetime]$_.created_timestamp
                        modified_timestamp = [datetime]$_.modified_timestamp
                        sha256 = $_.sha256
                    }
                }
                $LocalFile = @(Get-ChildItem $FilePath | Select-Object CreationTime,Name,LastWriteTime).foreach{
                    [PSCustomObject] @{
                        name = $_.Name
                        created_timestamp = $_.CreationTime
                        modified_timestamp = $_.LastWriteTime
                        sha256 = ((Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash).ToLower()
                    }
                }
                if ($LocalFile -and $CloudFile) {
                    if ($LocalFile.sha256 -eq $CloudFile.sha256) {
                        Write-Host "Matched hash values between local and cloud files..."
                    } else {
                        Write-Host "[CloudFile]"
                        $CloudFile | Select-Object name,created_timestamp,modified_timestamp,sha256 |
                            Format-List | Out-Host
                        Write-Host "[LocalFile]"
                        $LocalFile | Select-Object name,created_timestamp,modified_timestamp,sha256 |
                            Format-List | Out-Host
                        $FileChoice = $host.UI.PromptForChoice(
                            "'$Filename' exists in your 'Put' Files. Use existing version?",$null,
                            [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes","&No"),0)
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
                    Path = $FilePath
                    Name = $Filename
                    Description = "$ProcessName"
                    Comment = 'PSFalcon: Invoke-FalconDeploy'
                }
                Send-FalconPutFile @Param
            }
            if ($AddPut.writes.resources_affected -ne 1 -and !$CloudFile.id) {
                throw "Upload failed."
            }
            try {
                for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 1000) {
                    $Param = @{ HostId = ($HostArray[$i..($i + 999)]).device_id }
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
                        # Change to a 'temp' directory for each device by platform
                        Write-Host "Initiated session with $(($SessionHosts | Measure-Object).Count) host..."
                        foreach ($Pair in (@{
                            Windows = ($HostArray | Where-Object { $SessionHosts -contains $_.device_id -and
                                $_.platform_name -eq 'Windows' }).device_id
                            Mac = ($HostArray | Where-Object { $SessionHosts -contains $_.device_id -and
                                $_.platform_name -eq 'Mac' }).device_id
                            Linux = ($HostArray | Where-Object { $SessionHosts -contains $_.device_id -and
                                $_.platform_name -eq 'Linux' }).device_id
                        }).GetEnumerator().Where({ $_.Value })) {
                            $Param = @{
                                BatchId = $Session.batch_id
                                Command = 'cd'
                                OptionalHostId = $Pair.Value
                            }
                            if ($PSBoundParameters.Timeout) {
                                $Param['Timeout'] = $PSBoundParameters.Timeout
                            }
                            $TempDir = switch ($Pair.Key) {
                                'Windows' { '\Windows\Temp' }
                                'Mac'     { '/tmp' }
                                'Linux'   { '/tmp' }
                            }
                            $Param['Argument'] = $TempDir
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
                                    " $($Pair.Key) host...")
                                $Param = @{
                                    BatchId = $Session.batch_id
                                    Command = 'put'
                                    Argument = $Filename
                                    OptionalHostId = $CdHosts
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
                                    " $($Pair.Key) host...")
                                $ModParam = @{
                                    BatchId = $Session.batch_id
                                    Command = 'runscript'
                                    Argument = '-Raw=```chmod +x ' + "$($TempDir)/$($Filename)" + '```'
                                    OptionalHostId = $PutHosts
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
                                    " $($Pair.Key) host...")
                                $ArgString = if ($Pair.Key -eq 'Windows') {
                                    "$($TempDir)\$($Filename)"
                                } else {
                                    "$($TempDir)/$($Filename)"
                                }
                                if ($PSBoundParameters.Argument) {
                                    $ArgString += " -CommandLine=`"$($PSBoundParameters.Argument)`""
                                }
                                $Param = @{
                                    BatchId = $Session.batch_id
                                    Command = 'run'
                                    Argument = $ArgString
                                    OptionalHostId = $PutHosts
                                }
                                if ($PSBoundParameters.Timeout) { $Param['Timeout'] = $PSBoundParameters.Timeout }
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
                    Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime
                }
            }
        }
    }
}
function Invoke-FalconRtr {
<#
.SYNOPSIS
Start Real-time Response session,execute a command and output the result
.DESCRIPTION
Requires 'real-time-response:read','real-time-response:write' or 'real-time-response-admin:write'
depending on 'Command' provided.
.PARAMETER Command
Real-time Response command
.PARAMETER Argument
Arguments to include with the command
.PARAMETER Timeout
Length of time to wait for a result, in seconds
.PARAMETER QueueOffline
Add non-responsive Hosts to the offline queue
.PARAMETER HostId
Host identifier
.PARAMETER HostId
Host identifier
.PARAMETER GroupId
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding(DefaultParameterSetName='HostId')]
    param(
        [Parameter(ParameterSetName='HostId',Mandatory,Position=1)]
        [Parameter(ParameterSetName='GroupId',Mandatory,Position=1)]
        [ValidateSet('cat','cd','clear','cp','csrutil','cswindiag','encrypt','env','eventlog','filehash',
            'get','getsid','history','ifconfig','ipconfig','kill','ls','map','memdump','mkdir','mount',
            'mv','netstat','ps','put','put-and-run','reg delete','reg load','reg query','reg set',
            'reg unload','restart','rm','run','runscript','shutdown','umount','unmap','update history',
            'update install','update list','users','xmemdump','zip',IgnoreCase=$false)]
        [string]$Command,

        [Parameter(ParameterSetName='HostId',Position=2)]
        [Parameter(ParameterSetName='GroupId',Position=2)]
        [Alias('Arguments')]
        [string]$Argument,

        [Parameter(ParameterSetName='HostId',Position=3)]
        [Parameter(ParameterSetName='GroupId',Position=3)]
        [ValidateRange(30,600)]
        [int32]$Timeout,

        [Parameter(ParameterSetName='HostId')]
        [Parameter(ParameterSetName='GroupId')]
        [boolean]$QueueOffline,

        #[Parameter(ParameterSetName='HostId',ValueFromPipeline,Mandatory)]
        #[ValidatePattern('^\w{32}$')]
        #[Alias('device_id')]
        #[string]$HostId,

        [Parameter(ParameterSetName='HostId',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id','host_ids','HostIds')]
        [string[]]$HostId,

        [Parameter(ParameterSetName='GroupId',Mandatory)]
        [ValidatePattern('^\w{32}$')]
        [string]$GroupId
    )
    begin {
        if ($PSCmdlet.ParameterSetName -ne 'HostId') {
            function Initialize-Output ([array]$HostIds) {
                # Create initial array of output for each host
                ($HostIds).foreach{
                    $Item = [PSCustomObject] @{
                        aid = $_
                        batch_id = $null
                        session_id = $null
                        cloud_request_id = $null
                        complete = $false
                        offline_queued = $false
                        errors = $null
                        stderr = $null
                        stdout = $null
                    }
                    if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                        Add-Property $Item 'batch_get_cmd_req_id' $null
                    }
                    if ($PSBoundParameters.GroupId) {
                        Add-Property $Item 'host_group_id' $PSBoundParameters.GroupId
                    }
                    $Item
                }
            }
            if ($PSBoundParameters.Timeout -and $PSBoundParameters.Command -eq 'runscript' -and
            $PSBoundParameters.Argument -notmatch '-Timeout=\d{2,3}') {
                # Force 'Timeout' into 'Arguments' when using 'runscript'
                $PSBoundParameters.Argument += " -Timeout=$($PSBoundParameters.Timeout)"
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
                    QueueOffline = if ($PSBoundParameters.QueueOffline -eq $true) { $true } else { $false }
                }
                $Init = Start-FalconSession @InitParam
                $Request = if ($Init.session_id) {
                    # Set baseline command parameters
                    $CmdParam = @{ SessionId = $Init.session_id }
                    switch -Regex ($PSBoundParameters.Keys) {
                        '^(Command|Arguments)$' { $CmdParam[$_] = $PSBoundParameters.$_ }
                    }
                    Invoke-FalconAdminCommand @CmdParam
                }
                if ($Init.offline_queued -eq $false -and $Request.cloud_request_id) {
                    do {
                        # Retry command confirmation until result is provided
                        Start-Sleep -Seconds 5
                        $Confirm = Confirm-FalconAdminCommand -CloudRequestId $Request.cloud_request_id
                    } until (
                        $Confirm.complete -ne $false -or $Confirm.stdout -or $Confirm.stderr
                    )
                    $Confirm | ForEach-Object {
                        $CmdId = if ($_.task_id -and !$_.cloud_request_id) {
                            # Rename 'task_id' to 'cloud_request_id'
                            Add-Property $_ 'cloud_request_id' $_.task_id
                            $_.PSObject.Properties.Remove('task_id')
                            'cloud_request_id'
                        } else {
                            'task_id'
                        }
                        $_ | Select-Object session_id,$CmdId,complete,stdout,stderr | ForEach-Object {
                            if ($_.stdout -and $PSBoundParameters.Command -eq 'runscript') {
                                # Attempt to convert 'stdout' from Json for 'runscript'
                                $StdOut = try { $_.stdout | ConvertFrom-Json } catch { $null }
                                if ($StdOut) { $_.stdout = $StdOut }
                            }
                            $_
                        }
                    }
                } else {
                    $Request
                }
            } else {
                [array]$HostArray = if ($PSCmdlet.ParameterSetName -eq 'GroupId') {
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
                    [array]$Group = Initialize-Output $HostArray[$i..($i + 999)]
                    $InitParam = @{
                        HostId = $Group.aid
                        QueueOffline = if ($PSBoundParameters.QueueOffline -eq $true) { $true } else { $false }
                    }
                    # Define command request parameters
                    if ($InvokeCmd -eq 'Invoke-FalconBatchGet') {
                        $CmdParam = @{ FilePath = $PSBoundParameters.Argument }
                    } else {
                        $CmdParam = @{ Command = $PSBoundParameters.Command }
                        if ($PSBoundParameters.Argument) {
                            $CmdParam['Argument'] = $PSBoundParameters.Argument
                        }
                    }
                    if ($PSBoundParameters.Timeout) {
                        @($InitParam,$CmdParam).foreach{
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
                                Add-Property $_ 'batch_get_cmd_req_id' (
                                    $CmdRequest.batch_get_cmd_req_id)
                            }
                            $CmdContent
                        } else {
                            # Output result
                            Get-RtrResult -Object $CmdRequest -Output $InitResult | ForEach-Object {
                                if ($_.stdout -and $PSBoundParameters.Command -eq 'runscript') {
                                    # Attempt to convert 'stdout' from Json for 'runscript'
                                    $StdOut = try { $_.stdout | ConvertFrom-Json } catch { $null }
                                    if ($StdOut) { $_.stdout = $StdOut }
                                }
                                $_
                            }
                        }
                    }
                }
            }
        } catch {
            throw $_
        }
    }
}