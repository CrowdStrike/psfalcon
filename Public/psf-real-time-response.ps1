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
                    $Obj = [PSCustomObject]@{}
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
.PARAMETER GroupId
Host group identifier
.PARAMETER HostId
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Real-time-Response
#>
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName='HostIds')]
    param(
        [Parameter(ParameterSetName='HostId',Mandatory,Position=1)]
        [Parameter(ParameterSetName='GroupId',Mandatory,Position=1)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist or is a directory."
            }
        })]
        [string]$Path,
        [Parameter(ParameterSetName='HostId',Position=2)]
        [Parameter(ParameterSetName='GroupId',Position=2)]
        [Alias('Arguments')]
        [string]$Argument,
        [Parameter(ParameterSetName='HostId',Position=3)]
        [Parameter(ParameterSetName='GroupId',Position=3)]
        [ValidateRange(1,600)]
        [int32]$Timeout,
        [Parameter(ParameterSetName='HostId',Position=4)]
        [Parameter(ParameterSetName='GroupId',Position=4)]
        [boolean]$QueueOffline,
        [Parameter(ParameterSetName='GroupId',Mandatory)]
        [ValidatePattern('^\w{32}$')]
        [string]$GroupId,
        [Parameter(ParameterSetName='HostId',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}$')]
        [Alias('HostIds','device_id','host_ids','aid')]
        [string[]]$HostId
    )
    begin {
        # Fields to collect from 'Put' files list
        $PutFields = @('id','name','created_timestamp','modified_timestamp','sha256')
        function Write-RtrResult ($Object,$Step,$BatchId) {
            # Create output, append results and output to CSV
            $Output = foreach ($i in $Object) {
                [PSCustomObject]@{
                    aid = $i.aid
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
            Get-RtrResult $Object $Output | Export-Csv $OutputFile -Append -NoTypeInformation
        }
        # Set output file and executable details
        $OutputFile = Join-Path (Get-Location).Path "FalconDeploy_$(Get-Date -Format FileDateTime).csv"
        $FilePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        $Filename = "$([System.IO.Path]::GetFileName($FilePath))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($FilePath))"
        [System.Collections.Arraylist]$HostArray = @()
        [System.Collections.Arraylist]$IdArray = @()
    }
    process {
        if ($PSBoundParameters.GroupId) {
            if (($PSBoundParameters.GroupId | Get-FalconHostGroupMember -Total) -gt 10000) {
                # Stop if number of members exceeds API limit
                throw "Group size exceeds maximum number of results. [10,000]"
            } else {
                # Retrieve Host Group member device_id and platform_name
                @($PSBoundParameters.GroupId | Get-FalconHostGroupMember -Detailed -All |
                    Select-Object device_id,platform_name).foreach{ [void]$HostArray.Add($_) }
            }
        } elseif ($PSBoundParameters.HostId) {
            # Use provided Host identifiers
            @($PSBoundParameters.HostId).foreach{ [void]$IdArray.Add($_) }
        }
    }
    end {
        if ($IdArray) {
            @(Get-FalconHost -Id @($IdArray | Select-Object -Unique) |
                Select-Object device_id,platform_name).foreach{ [void]$HostArray.Add($_) }
        }
        if ($HostArray) {
            try {
                Write-Host "Checking cloud for existing file..."
                $CloudFile = @(Get-FalconPutFile -Filter "name:['$Filename']" -Detailed |
                Select-Object $PutFields).foreach{
                    [PSCustomObject]@{
                        id = $_.id
                        name = $_.name
                        created_timestamp = [datetime]$_.created_timestamp
                        modified_timestamp = [datetime]$_.modified_timestamp
                        sha256 = $_.sha256
                    }
                }
                $LocalFile = @(Get-ChildItem $FilePath | Select-Object CreationTime,Name,LastWriteTime).foreach{
                    [PSCustomObject]@{
                        name = $_.Name
                        created_timestamp = $_.CreationTime
                        modified_timestamp = $_.LastWriteTime
                        sha256 = ((Get-FileHash $FilePath).Hash).ToLower()
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
                            $RemovePut = $CloudFile.id | Remove-FalconPutFile
                            if ($RemovePut.writes.resources_affected -eq 1) {
                                Write-Host "Removed CloudFile: $($CloudFile.id)"
                            }
                        }
                    }
                }
            } catch {
                throw $_
            }
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
            if ($AddPut.writes.resources_affected -ne 1 -and !$CloudFile.id) { throw "Upload failed." }
            try {
                for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 1000) {
                    $Param = @{ Id = @($HostArray[$i..($i + 999)].device_id) }
                    switch -Regex ($PSBoundParameters.Keys) {
                        '(QueueOffline|Timeout)' { $Param[$_] = $PSBoundParameters.$_ }
                    }
                    $Session = Start-FalconSession @Param
                    $SessionHosts = if ($Session.batch_id) {
                        # Output result to CSV and return list of successful 'session_start' hosts
                        Write-RtrResult $Session.hosts 'session_start' $Session.batch_id
                        ($Session.hosts | Where-Object { $_.complete -eq $true -or
                            $_.offline_queued -eq $true }).aid
                    }
                    if ($SessionHosts) {
                        # Change to a 'temp' directory for each device by platform
                        Write-Host "Initiated session with $(($SessionHosts | Measure-Object).Count) host(s)..."
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
                            if ($PSBoundParameters.Timeout) { $Param['Timeout'] = $PSBoundParameters.Timeout }
                            $TempDir = switch ($Pair.Key) {
                                'Windows' { '\Windows\Temp' }
                                'Mac'     { '/tmp' }
                                'Linux'   { '/tmp' }
                            }
                            $Param['Argument'] = $TempDir
                            $CmdCd = Invoke-FalconAdminCommand @Param
                            $CdHosts = if ($CmdCd) {
                                # Output result to CSV and return list of successful 'cd_temp' hosts
                                Write-RtrResult $CmdCd 'cd_temp' $Session.batch_id
                                ,($CmdCd | Where-Object { ($_.complete -eq $true -and !$_.stderr) -or
                                    $_.offline_queued -eq $true }).aid
                            }
                            $PutHosts = if ($CdHosts) {
                                # Invoke 'put' on successful hosts
                                Write-Host ("Sending $Filename to $(($CdHosts | Measure-Object).Count)" +
                                    " $($Pair.Key) host(s)...")
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
                                    Write-RtrResult $CmdPut 'put_file' $Session.batch_id
                                    ($CmdPut | Where-Object { ($_.complete -eq $true -and !$_.stderr) -or
                                        $_.offline_queued -eq $true }).aid
                                }
                            }
                            if ($PutHosts -and $Pair.Key -eq 'Linux') {
                                # Modify 'put' file if running on Linux
                                Write-Host ("Modifying $Filename on $(($PutHosts | Measure-Object).Count)" +
                                    " $($Pair.Key) host(s)...")
                                $ModParam = @{
                                    BatchId = $Session.batch_id
                                    Command = 'runscript'
                                    Argument = '-Raw=```chmod +x ' + "$($TempDir)/$($Filename)" + '```'
                                    OptionalHostId = $PutHosts
                                }
                                $CmdMod = Invoke-FalconAdminCommand @ModParam
                                $PutHosts = if ($CmdMod) {
                                    # Output result to CSV and return list of successful 'mod_file' hosts
                                    Write-RtrResult $CmdMod 'mod_file' $Session.batch_id
                                    ($CmdMod | Where-Object { ($_.complete -eq $true -and !$_.stderr) -or
                                        $_.offline_queued -eq $true }).aid
                                }
                            }
                            if ($PutHosts) {
                                # Invoke 'run'
                                Write-Host ("Starting $Filename on $(($PutHosts | Measure-Object).Count)" +
                                    " $($Pair.Key) host(s)...")
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
                                    Write-RtrResult $CmdRun 'run_file' $Session.batch_id
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
.PARAMETER GroupId
Host group identifier
.PARAMETER HostId
Host identifier
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
        [Parameter(ParameterSetName='GroupId',Mandatory)]
        [ValidatePattern('^\w{32}$')]
        [string]$GroupId,
        [Parameter(ParameterSetName='HostId',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}$')]
        [Alias('device_id','host_ids','aid','HostIds')]
        [string[]]$HostId
    )
    begin {
        function Initialize-Output ($Array) {
            # Create initial array of output for each host
            @($Array).foreach{
                [PSCustomObject]@{
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
            }
        }
        if ($PSBoundParameters.Timeout -and $PSBoundParameters.Command -eq 'runscript' -and
        $PSBoundParameters.Argument -notmatch '-Timeout=\d{2,3}') {
            # Force 'Timeout' into 'Arguments' when using 'runscript'
            $PSBoundParameters.Argument += " -Timeout=$($PSBoundParameters.Timeout)"
        }
        [System.Collections.Arraylist]$IdArray = @()
    }
    process {
        if ($PSBoundParameters.GroupId) {
            if (($PSBoundParameters.GroupId | Get-FalconHostGroupMember -Total) -gt 10000) {
                # Stop if number of members exceeds API limit
                throw "Group size exceeds maximum number of results. [10,000]"
            } else {
                # Retrieve Host Group member device_id and platform_name
                @($PSBoundParameters.GroupId | Get-FalconHostGroupMember -All).foreach{ [void]$IdArray.Add($_) }
            }
        } elseif ($PSBoundParameters.HostId) {
            # Use provided Host identifiers
            @($PSBoundParameters.HostId).foreach{ [void]$IdArray.Add($_) }
        }
    }
    end {
        if ($IdArray) {
            $Output = Initialize-Output @($IdArray | Select-Object -Unique)
            if ($PSBoundParameters.GroupId) {
                # Append 'group_id' field to results
                @($Output).foreach{ Add-Property $_ 'group_id' $PSBoundParameters.GroupId }
            }
            if ($PSBoundParameters.Command -eq 'get' -and $IdArray.Count -gt 1) {
                # Append 'batch_get_cmd_req_id' field to results
                @($Output).foreach{ Add-Property $_ 'batch_get_cmd_req_id' $null }
            }
            $Init = @{}
            @('QueueOffline').foreach{ if ($PSBoundParameters.$_) { $Init[$_] = $PSBoundParameters.$_ }}
            # Start session and capture result
            $InitReq = $IdArray | Start-FalconSession @Init
            $Output = if ($InitReq.hosts) {
                @(Get-RtrResult $InitReq.hosts $Output).foreach{
                    # Clear 'stdout' from batch initialization
                    $_.stdout = $null
                    $_
                }
            } else {
                Get-RtrResult $InitReq $Output
            }
            if ($InitReq.batch_id -or $InitReq.session_id) {
                # Issue command and capture result
                $InvokeCmd = Get-RtrCommand $PSBoundParameters.Command
                $Cmd = @{ Command = $PSBoundParameters.Command }
                if ($PSBoundParameters.QueueOffline -eq $false) { $Cmd['Confirm'] = $true }
                @('Argument','Timeout').foreach{ if ($PSBoundParameters.$_) { $Cmd[$_] = $PSBoundParameters.$_ }}
                $CmdReq = $InitReq | & $InvokeCmd @Cmd
                foreach ($Result in @(Get-RtrResult $CmdReq $Output)) {
                    # Clear 'stdout' for batch 'get' requests
                    if ($Result.stdout -and $Result.batch_get_cmd_req_id) { $Result.stdout = $null }
                    if ($Result.stdout -and $Cmd.Command -eq 'runscript') {
                        # Attempt to convert 'stdout' from Json for 'runscript'
                        $StdOut = try { $Result.stdout | ConvertFrom-Json } catch { $null }
                        if ($StdOut) { $Result.stdout = $StdOut }
                    }
                    $Result
                }
            }
        }
    }
}