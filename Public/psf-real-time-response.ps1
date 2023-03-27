function Get-FalconQueue {
<#
.SYNOPSIS
Create a report of Real-time Response commands in the offline queue
.DESCRIPTION
Creates a CSV of pending Real-time Response commands and their related session information. By default, sessions
within the offline queue expire 7 days after creation. Sessions can have additional commands appended to them to
extend their expiration time.

Additional host information can be appended to the results using the 'Include' parameter.

Requires 'Real Time Response: Read', 'Real Time Response: Write' and 'Real Time Response (Admin): Write'.
.PARAMETER Days
Number of days worth of sessions to retrieve [default: 7]
.PARAMETER Include
Include additional properties
.PARAMETER HostId
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconQueue
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
        [string[]]$Include,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [string[]]$HostId
    )
    begin {
        # Default to 7 days when not provided
        if (!$Days) { $Days = 7 }
        $Select = @{
            # Properties to select from requests and/or objects
            Session = 'aid','user_id','user_uuid','id','created_at','deleted_at','status'
            Command = 'stdout','stderr','complete'
            Output = 'aid','user_id','user_uuid','session_id','session_created_at','session_deleted_at',
                'session_status','cloud_request_id','command_created_at','command_updated_at',
                'command_deleted_at','base_command','command_string','command_status','command_complete',
                'command_stdout','command_stderr'
        }
        # Set output filepath and base FQL query
        $Csv = Join-Path (Get-Location).Path "FalconQueue_$(Get-Date -Format FileDateTime).csv"
        $BaseFql = "commands_queued:1+(deleted_at:null,created_at:>'now-$($Days)d')"
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($HostId) { @($HostId).foreach{ $List.Add($_) }}}
    end {
        [string[]]$Filter = if ($List) {
            $List = $List | Where-Object { ![string]::IsNullOrEmpty($_) } | Select-Object -Unique
            for ($i = 0; $i -lt $List.Count; $i += 17) {
                # Create individual filter statements for groups of host identifiers
                [string]$IdList = "($((@($List[$i..($i + 16)]).foreach{ "aid:'$_'" }) -join ','))"
                $BaseFql,$IdList -join '+'
            }
        } else {
            $BaseFql
        }
        @($Filter).foreach{
            @(Get-FalconSession -Filter $_ -Detailed -All | Select-Object id,device_id).foreach{
                [object[]]$HostList = if ($Include) {
                    # Retrieve host information for hosts involved in sessions
                    $_.device_id | Get-FalconHost -EA 0 | Select-Object @($Include + 'device_id')
                }
                foreach ($Session in ($_.id | Get-FalconSession -Queue)) {
                    # Create base output for each queued session
                    $BaseObj = @{}
                    @($Session | Select-Object $Select.Session).foreach{
                        @($_.PSObject.Properties).foreach{
                            $Name = if ($_.Name -match '^(id|(created|deleted|updated)_at|status)$') {
                                # Prefix session-related columns
                                'session',$_.Name -join '_'
                            } else {
                                $_.Name
                            }
                            $BaseObj[$Name] = $_.Value
                        }
                    }
                    if ($Include -and $HostList) {
                        @($HostList.Where({ $_.device_id -eq $BaseObj.aid })).foreach{
                            @($_.PSObject.Properties.Where({ $_.Name -ne 'device_id' })).foreach{
                                # Append 'Include' properties to base output
                                $BaseObj[$_.Name] = $_.Value
                            }
                        }
                    }
                    @($Session.commands).foreach{
                        # Build upon base output for each command
                        $Obj = $BaseObj.Clone()
                        @($_.PSObject.Properties).foreach{
                            $Name = if ($_.Name -match '^((created|deleted|updated)_at|status)$') {
                                # Prefix command-related columns
                                'command',$_.Name -join '_'
                            } else {
                                $_.Name
                            }
                            $Obj[$Name] = $_.Value
                        }
                        if ($Obj.command_status -eq 'FINISHED') {
                            [string]$ConfirmCmd = Get-RtrCommand $Obj.base_command -ConfirmCommand
                            @($Obj.cloud_request_id | & $ConfirmCmd -EA 4 | Select-Object $Select.Command).foreach{
                                @($_.PSObject.Properties).foreach{
                                    # Append 'stdout','stderr','complete' for 'FINISHED' command(s)
                                    $Obj[('command',$_.Name -join '_')] = $_.Value
                                }
                            }
                        } else {
                            $Obj.command_complete = $false
                        }
                        $Output = if ($Include) {
                            [PSCustomObject]$Obj | Select-Object @($Select.Output + $Include)
                        } else {
                            [PSCustomObject]$Obj | Select-Object $Select.Output
                        }
                        try { $Output | Export-Csv $Csv -NoTypeInformation -Append } catch { $Output }
                    }
                }
            }
        }
        if (Test-Path $Csv) { Get-ChildItem $Csv | Select-Object FullName,Length,LastWriteTime }
    }
}
function Invoke-FalconDeploy {
<#
.SYNOPSIS
Deploy and run an executable using Real-time Response
.DESCRIPTION
'Put' files will be checked for identical file names, and if any are found, the Sha256 hash values will be
compared between your local and cloud files. If they are different, a prompt will appear asking which file to use.

After ensuring that the 'Put' file is available, a Real-time Response session will be started for the designated
host(s) (or members of the Host Group), 'mkdir' will create a folder ('FalconDeploy_<FileDateTime>') within the
appropriate temporary folder (\Windows\Temp or /tmp), 'cd' will navigate to the new folder, and the target file or
archive will be 'put' into that folder. If the target is an archive, it will be extracted, and the designated
'Run' file will be executed. If the target is a file, it will be 'run'.

Details of each step will be output to a CSV file in your current directory.

Requires 'Hosts: Read', 'Real Time Response (Admin): Write'.
.PARAMETER File
Name of a 'CloudFile' or path to a local executable to upload
.PARAMETER Archive
Name of a 'CloudFile' or path to a local archive (zip, tar, tar.gz, tgz) to upload
.PARAMETER Run
Name of the file to run once extracted from the target archive
.PARAMETER Argument
Arguments to include when running the target executable
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 60]
.PARAMETER QueueOffline
Add non-responsive Hosts to the offline queue
.PARAMETER Include
Include additional properties
.PARAMETER GroupId
Host group identifier
.PARAMETER HostId
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconDeploy
#>
    [CmdletBinding(DefaultParameterSetName='HostId_File',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='HostId_File',Mandatory,Position=1)]
        [Parameter(ParameterSetName='GroupId_File',Mandatory,Position=1)]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) {
                $true
            } else {
                $FileName = [System.IO.Path]::GetFileName($_)
                if (Get-FalconPutFile -Filter "name:['$FileName']") {
                    $true
                } else {
                    throw "Cannot find path '$_' because it does not exist or is a directory."
                }
            }
        })]
        [Alias('Path','FullName')]
        [string]$File,
        [Parameter(ParameterSetName='HostId_Archive',Mandatory)]
        [Parameter(ParameterSetName='GroupId_Archive',Mandatory)]
        [ValidateScript({
            if ($_ -match '\.(zip|tar(.gz)?|tgz)$') {
                if (Test-Path $_ -PathType Leaf) {
                    $true
                } else {
                    $FileName = [System.IO.Path]::GetFileName($_)
                    if (Get-FalconPutFile -Filter "name:['$FileName']") {
                        $true
                    } else {
                        throw "Cannot find path '$_' because it does not exist or is a directory."
                    }
                }
            } else {
                throw "'$_' does not match expected file extension: 'zip', 'tar', 'tar.gz', or 'tgz'."
            }
        })]
        [string]$Archive,
        [Parameter(ParameterSetName='HostId_Archive',Mandatory,Position=2)]
        [Parameter(ParameterSetName='GroupId_Archive',Mandatory,Position=2)]
        [string]$Run,
        [Parameter(ParameterSetName='HostId_File',Position=2)]
        [Parameter(ParameterSetName='GroupId_File',Position=2)]
        [Parameter(ParameterSetName='HostId_Archive',Position=3)]
        [Parameter(ParameterSetName='GroupId_Archive',Position=3)]
        [Alias('Arguments')]
        [string]$Argument,
        [Parameter(ParameterSetName='HostId_File',Position=3)]
        [Parameter(ParameterSetName='GroupId_File',Position=3)]
        [Parameter(ParameterSetName='HostId_Archive',Position=4)]
        [Parameter(ParameterSetName='GroupId_Archive',Position=4)]
        [ValidateRange(30,600)]
        [int32]$Timeout,
        [Parameter(ParameterSetName='HostId_File',Position=4)]
        [Parameter(ParameterSetName='GroupId_File',Position=4)]
        [Parameter(ParameterSetName='HostId_Archive',Position=5)]
        [Parameter(ParameterSetName='GroupId_Archive',Position=5)]
        [boolean]$QueueOffline,
        [Parameter(ParameterSetName='HostId_File',Position=5)]
        [Parameter(ParameterSetName='GroupId_File',Position=5)]
        [Parameter(ParameterSetName='HostId_Archive',Position=6)]
        [Parameter(ParameterSetName='GroupId_Archive',Position=6)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','hostname','last_seen','local_ip',
            'mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
            'serial_number','system_manufacturer','system_product_name','tags',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='GroupId_File',Mandatory)]
        [Parameter(ParameterSetName='GroupId_Archive',Mandatory)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$GroupId,
        [Parameter(ParameterSetName='HostId_File',Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [Parameter(ParameterSetName='HostId_Archive',Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('device_id','host_ids','aid','id','HostIds')]
        [string[]]$HostId
    )
    begin {
        # Define output file, temporary folder, file detail and archive expansion/chmod scripts
        [string]$DeployName = "FalconDeploy_$(Get-Date -Format FileDateTime)"
        [string]$Csv = Join-Path (Get-Location).Path "$DeployName.csv"
        [string]$FilePath = if ($Archive) {
            $Script:Falcon.Api.Path($Archive)
        } else {
            $Script:Falcon.Api.Path($File)
        }
        [string]$PutFile = [System.IO.Path]::GetFileName($FilePath)
        [string]$RunFile = if ($File) { $PutFile } else { $Run }
        function Update-CloudFile ([string]$FileName,[string]$FilePath) {
            # Fields to collect from 'Put' files list
            $Fields = @('id','name','created_timestamp','modified_timestamp','sha256')
            try {
                # Compare 'CloudFile' and 'LocalFile'
                Write-Host "[Invoke-FalconDeploy] Checking cloud for existing file..."
                $CloudFile = @(Get-FalconPutFile -Filter "name:['$FileName']" -Detailed |
                Select-Object $Fields).foreach{
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
                        Write-Host "[Invoke-FalconDeploy] Matched hash values between local and cloud files."
                    } else {
                        # Prompt for file choice and remove 'CloudFile' if 'LocalFile' is chosen
                        Write-Host "[CloudFile]"
                        $CloudFile | Select-Object name,created_timestamp,modified_timestamp,sha256 |
                            Format-List | Out-Host
                        Write-Host "[LocalFile]"
                        $LocalFile | Select-Object name,created_timestamp,modified_timestamp,sha256 |
                            Format-List | Out-Host
                        $FileChoice = $host.UI.PromptForChoice(
                            "[Invoke-FalconDeploy] '$FileName' exists in your 'Put' Files. Use existing version?",
                            $null,[System.Management.Automation.Host.ChoiceDescription[]]@("&Yes","&No"),0)
                        if ($FileChoice -eq 0) {
                            Write-Host "[Invoke-FalconDeploy] Proceeding with CloudFile '$($CloudFile.id)'..."
                        } else {
                            [object]$RemovePut = $CloudFile.id | Remove-FalconPutFile
                            if ($RemovePut.writes.resources_affected -eq 1) {
                                Write-Host "[Invoke-FalconDeploy] Removed CloudFile '$($CloudFile.id)'."
                            }
                        }
                    }
                }
            } catch {
                throw $_
            }
            if ($RemovePut.writes.resources_affected -eq 1 -or !$CloudFile) {
                # Upload 'LocalFile' and output result
                Write-Host "[Invoke-FalconDeploy] Uploading '$FileName'..."
                $Param = @{
                    Path = $FilePath
                    Name = $FileName
                    Description = "Invoke-FalconDeploy [$((Show-FalconModule).UserAgent)]"
                    Comment = "Invoke-FalconDeploy [$((Show-FalconModule).UserAgent)]"
                }
                $AddPut = Send-FalconPutFile @Param
                if (!$AddPut) {
                    throw "Upload failed."
                } elseif ($AddPut -and $AddPut.writes.resources_affected -eq 1) {
                    Write-Host "[Invoke-FalconDeploy] Upload complete."
                }
            }
        }
        function Write-RtrResult ([object[]]$Object,[string]$Step) {
            # Create output, append results and output specified fields to CSV, and return successful hosts
            [string[]]$Fields = 'aid','batch_id','cloud_request_id','complete','deployment_step','errors',
                'offline_queued','session_id','stderr','stdout'
            if ($Include) { $Fields += $Include }
            $Output = @($Object).foreach{
                $i = [PSCustomObject]@{ aid = $_.aid; deployment_step = $Step }
                if ($Include) {
                    # Append 'Include' fields to output
                    @($HostList).Where({ $_.device_id -eq $i.aid }).foreach{
                        @($_.PSObject.Properties).Where({ $Include -contains $_.Name }).foreach{
                            Set-Property $i $_.Name $_.Value
                        }
                    }
                }
                $i
            }
            Get-RtrResult $Object $Output | Select-Object $Fields | Export-Csv $Csv -Append -NoTypeInformation
            ($Object | Where-Object { ($_.complete -eq $true -and !$_.stderr) -or
                $_.offline_queued -eq $true }).aid
        }
        [System.Collections.Generic.List[object]]$HostList = @()
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($GroupId) {
            if ((Get-FalconHostGroupMember -Id $GroupId -Total) -gt 10000) {
                # Stop if number of members exceeds API limit
                throw "Group size exceeds maximum number of results. [10,000]"
            } else {
                # Retrieve Host Group member device_id and platform_name
                [string[]]$Select = 'device_id','platform_name'
                if ($Include) { $Select += ($Include | Where-Object { $_ -ne 'platform_name' })}
                @(Get-FalconHostGroupMember -Id $GroupId -Detailed -All | Select-Object $Select).foreach{
                    $HostList.Add($_)
                }
            }
        } elseif ($HostId) {
            # Use provided Host identifiers
            @($HostId).foreach{ $List.Add($_) }
        }
    }
    end {
        if ($List) {
            # Use Host identifiers to also retrieve 'platform_name' and 'Include' fields
            [string[]]$Select = 'device_id','platform_name'
            if ($Include) { $Select += ($Include | Where-Object { $_ -ne 'platform_name' })}
            @($List | Select-Object -Unique | Get-FalconHost | Select-Object $Select).foreach{
                $HostList.Add($_)
            }
        }
        if ($HostList) {
            # Check for existing 'CloudFile' and upload 'LocalFile' if chosen
            if (Test-Path $FilePath -PathType Leaf) { Update-CloudFile $PutFile $FilePath }
            try {
                # Force a base timeout of 60
                if (!$Timeout) { $Timeout = 60 }
                for ($i = 0; $i -lt ($HostList | Measure-Object).Count; $i += 10000) {
                    # Start Real-time Response sessions in groups of 10,000 with 'HostTimeout' to force batch
                    $Param = @{
                        Id = @($HostList[$i..($i + 9999)].device_id)
                        Timeout = $Timeout
                        HostTimeout = [math]::Truncate($Timeout*.9)
                    }
                    if ($QueueOffline) { $Param['QueueOffline'] = $QueueOffline }
                    $Session = Start-FalconSession @Param
                    [string[]]$SessionIds = if ($Session.batch_id) {
                        # Output result to CSV and return list of successful 'init' hosts
                        Write-RtrResult $Session.hosts init $Session.batch_id
                    }
                    if ($SessionIds) {
                        # Keep RTR session alive and Change to a 'temp' directory for each device by platform
                        $JobId = Start-RtrUpdate $Session.batch_id $Timeout
                        Write-Host "[Invoke-FalconDeploy] Initiated session with $(($SessionIds |
                            Measure-Object).Count) host(s)..."
                        foreach ($Pair in (@{
                            Windows = ($HostList | Where-Object { $SessionIds -contains $_.device_id -and
                                $_.platform_name -eq 'Windows' }).device_id
                            Mac = ($HostList | Where-Object { $SessionIds -contains $_.device_id -and
                                $_.platform_name -eq 'Mac' }).device_id
                            Linux = ($HostList | Where-Object { $SessionIds -contains $_.device_id -and
                                $_.platform_name -eq 'Linux' }).device_id
                        }).GetEnumerator().Where({ $_.Value })) {
                            # Define target temporary folder
                            [string]$TempDir = switch ($Pair.Key) {
                                'Windows' { "\Windows\Temp\$DeployName" }
                                'Mac' { "/tmp/$DeployName" }
                                'Linux' { "/tmp/$DeployName" }
                            }
                            # Script content for 'runscript' by platform and 'Archive' or 'File'
                            $Runscript = @{
                                Linux = @{
                                    Archive = if ($PutFile -match '\.(tar(.gz)?|tgz)$') {
                                        "if ! command -v tar &> /dev/null; then echo 'Missing application: tar';" +
                                            " exit 1; fi; tar -xf $PutFile; chmod +x $($TempDir,$RunFile -join
                                            '/'); exit 0"
                                    } else {
                                        "if ! command -v unzip &> /dev/null; then echo 'Missing application: unz" +
                                            "ip'; exit 1; fi; unzip $PutFile; chmod +x $($TempDir,$RunFile -join
                                            '/'); exit 0"
                                    }
                                    File = "chmod +x $($TempDir,$PutFile -join '/')"
                                }
                                Mac = @{
                                    Archive = if ($PutFile -match '\.(tar(.gz)?|tgz)$') {
                                        "if ! command -v tar &> /dev/null; then echo 'Missing application: tar';" +
                                            " exit 1; fi; tar -xf $PutFile; chmod +x $($TempDir,$RunFile -join
                                            '/'); exit 0"
                                    } else {
                                        "if ! command -v unzip &> /dev/null; then echo 'Missing application: unz" +
                                            "ip'; exit 1; fi; unzip $PutFile; chmod +x $($TempDir,$RunFile -join
                                            '/'); exit 0"
                                    }
                                }
                                Windows = @{ Archive = "Expand-Archive $($TempDir,$PutFile -join '\') $TempDir" }
                            }
                            foreach ($Cmd in @('mkdir','cd','put','runscript','run')) {
                                # Define Real-time Response command parameters
                                $Param = @{
                                    BatchId = $Session.batch_id
                                    Command = if ($Cmd -eq 'run') { 'runscript' } else { $Cmd }
                                    Argument = switch ($Cmd) {
                                        'mkdir' { $TempDir }
                                        'cd' { $TempDir }
                                        'put' { $PutFile }
                                        'runscript' {
                                            # Get 'Archive' or 'File' script by platform
                                            $Script = if ($Archive) {
                                                $Runscript.($Pair.Key).Archive
                                            } else {
                                                $Runscript.($Pair.Key).File
                                            }
                                            if ($Script) { '-Raw=```{0}```' -f $Script }
                                        }
                                        'run' {
                                            [string]$Join = if ($Pair.Key -eq 'Windows') { '\' } else { '/' }
                                            if ($Pair.Key -eq 'Windows') {
                                                # Use 'runscript' to start process and avoid timeout
                                                [string]$String = if ($Argument) {
                                                    "Set-Location $TempDir;$($TempDir,$RunFile -join $Join)",
                                                        $Argument -join ' '
                                                } else {
                                                    "Set-Location $TempDir;$($TempDir,$RunFile -join $Join)"
                                                }
                                                [string]$Executable = if ($RunFile -match '\.cmd$') {
                                                    'cmd',"'/c $String'" -join ' '
                                                } else {
                                                    'powershell.exe',"'-c &{$String}'" -join ' '
                                                }
                                                '-Raw=```Start-Process',$Executable,
                                                "-RedirectStandardOutput '$($TempDir,'stdout.log' -join $Join)'",
                                                "-RedirectStandardError '$($TempDir,'stderr.log' -join $Join)'",
                                                ('-PassThru | ForEach-Object { "The process was successfully sta' +
                                                'rted"'),'}```' -join ' '
                                            } elseif ($Pair.Key -match '^(Linux|Mac)$') {
                                                # Use 'runscript' to start background process and avoid timeout
                                                [string]$String = if ($Argument) {
                                                    ($TempDir,$RunFile -join $Join),$Argument -join ' '
                                                } else {
                                                    $TempDir,$RunFile -join $Join
                                                }
                                                $String = "'$String > $($TempDir,'stdout.log' -join
                                                    $Join) 2> $($TempDir,'stderr.log' -join $Join) &'"
                                                if ($Pair.Key -eq 'Linux') {
                                                    ('-Raw=```(bash -c {0}); if [[ $? -eq 0 ]]; then echo "The p' +
                                                        'rocess was successfully started"; fi```') -f $String
                                                } else {
                                                    ('-Raw=```(zsh -c {0}); if [[ $? -eq 0 ]]; then echo "The pr' +
                                                    'ocess was successfully started"; fi```') -f $String
                                                }
                                            }
                                        }
                                    }
                                    OptionalHostId = if ($Cmd -eq 'mkdir') { $Pair.Value } else { $Optional }
                                    Timeout = if ($Timeout) { $Timeout } else { 60 }
                                }
                                if ($Param.OptionalHostId -and $Param.Argument) {
                                    # Issue command, output result to CSV and capture successful values
                                    Write-Host "[Invoke-FalconDeploy] Issuing '$Cmd' to $(($Param.OptionalHostId |
                                        Measure-Object).Count) $($Pair.Key) host(s)..."
                                    [string]$Step = if ($Cmd -eq 'runscript') { 'extract' } else { $Cmd }
                                    [string[]]$Optional = Write-RtrResult (
                                        Invoke-FalconAdminCommand @Param) $Step $Session.batch_id
                                }
                            }
                        }
                        Stop-RtrUpdate $JobId
                    }
                }
            } catch {
                throw $_
            } finally {
                if (Test-Path $Csv) { Get-ChildItem $Csv | Select-Object FullName,Length,LastWriteTime }
            }
        }
    }
}
function Invoke-FalconRtr {
<#
.SYNOPSIS
Start a Real-time Response session, execute a command and output the result
.DESCRIPTION
Requires 'Real Time Response: Read', 'Real Time Response: Write' or 'Real Time Response (Admin): Write'
depending on 'Command' provided, plus related permission(s) for 'Include' selection(s).
.PARAMETER Command
Real-time Response command
.PARAMETER Argument
Arguments to include with the command
.PARAMETER Timeout
Length of time to wait for a result, in seconds [default: 600]
.PARAMETER QueueOffline
Add non-responsive hosts to the offline queue
.PARAMETER Include
Include additional properties
.PARAMETER GroupId
Host group identifier
.PARAMETER HostId
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconRtr
#>
    [CmdletBinding(DefaultParameterSetName='HostId',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='HostId',Mandatory,Position=1)]
        [Parameter(ParameterSetName='GroupId',Mandatory,Position=1)]
        [string]$Command,
        [Parameter(ParameterSetName='HostId',Position=2)]
        [Parameter(ParameterSetName='GroupId',Position=2)]
        [Alias('Arguments')]
        [string]$Argument,
        [Parameter(ParameterSetName='HostId',Position=3)]
        [Parameter(ParameterSetName='GroupId',Position=3)]
        [ValidateRange(30,600)]
        [int32]$Timeout,
        [Parameter(ParameterSetName='HostId',Position=4)]
        [Parameter(ParameterSetName='GroupId',Position=4)]
        [boolean]$QueueOffline,
        [Parameter(ParameterSetName='HostId',Position=5)]
        [Parameter(ParameterSetName='GroupId',Position=5)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','hostname','last_seen','local_ip',
            'mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
            'serial_number','system_manufacturer','system_product_name','tags',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='GroupId',Mandatory)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$GroupId,
        [Parameter(ParameterSetName='HostId',Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('device_id','host_ids','aid','id','HostIds')]
        [string[]]$HostId
    )
    begin { [System.Collections.Generic.List[string]]$List = @() }
    process {
        if ($GroupId) {
            if ((Get-FalconHostGroupMember -Id $GroupId -Total) -gt 10000) {
                # Stop if number of HostGroup members exceeds API limit
                throw "Group size exceeds maximum number of results. [10,000]"
            } else {
                # Retrieve HostGroup members
                @(Get-FalconHostGroupMember -Id $GroupId -All).foreach{ $List.Add($_) }
            }
        } elseif ($HostId) {
            # Use provided Host identifiers
            @($HostId).foreach{ $List.Add($_) }
        }
    }
    end {
        if ($List) {
            # Gather list of unique host identifiers and append 'GroupId' when present
            [object[]]$HostList = @($List | Select-Object -Unique).foreach{ [PSCustomObject]@{ aid = $_ }}
            if ($GroupId) { @($HostList).foreach{ Set-Property $_ 'group_id' $GroupId }}
            if ($Include) {
                foreach ($i in (Get-FalconHost -Id $HostList.aid | Select-Object @($Include + 'device_id'))) {
                    foreach ($p in @($i.PSObject.Properties.Where({ $_.Name -ne 'device_id' }))) {
                        @($HostList).Where({ $_.aid -eq $i.device_id }).foreach{
                            # Append 'Include' fields to output
                            Set-Property $_ $p.Name $p.Value
                        }
                    }
                }
            }
            # Set default timeout of 600 seconds when not defined
            if (!$Timeout) { $Timeout = 600 }
            if ($Command -eq 'runscript' -and $Argument -notmatch '-Timeout=\d+') {
                # Set 'runscript' timeout when not present in 'Argument'
                $Argument += if (($HostList | Measure-Object).Count -gt 1) {
                    # Just under $Timeout for batch session
                    " -Timeout=$($Timeout-2)"
                } else {
                    # 3600 seconds for single-host session
                    " -Timeout=3600"
                }
            }
            for ($i = 0; $i -lt ($HostList | Measure-Object).Count; $i += 10000) {
                try {
                    # Start Real-time Response session in groups of up to 10,000 hosts
                    [object[]]$Output = $HostList[$i..($i + 9999)]
                    $Init = @{ Id = $Output.aid; Timeout = $Timeout; QueueOffline = $QueueOffline }
                    $InitReq = Start-FalconSession @Init
                    if ($InitReq.batch_id -or $InitReq.session_id) {
                        $JobId = Start-RtrUpdate $InitReq $Timeout
                        # Output verbose message with batch_id or session_id
                        [string[]]$Message = if ($InitReq.batch_id) {
                            'batch_id:',$InitReq.batch_id,"[$(@($InitReq.hosts).Where({
                                $_.complete -eq $true -or $_.offline_queued -eq $true
                            }).Count) host(s)]"
                        } else {
                            'session_id:',$InitReq.session_id
                        }
                        $PSCmdlet.WriteVerbose("[Invoke-FalconRtr] $($Message -join ' ')")
                        [object[]]$Output = if ($InitReq.batch_id) {
                            @(Get-RtrResult $InitReq.hosts $Output).foreach{
                                # Clear 'stdout' from batch initialization
                                if ($_.stdout) { $_.stdout = $null }
                                $_
                            }
                        } elseif ($InitReq.session_id) {
                            Get-RtrResult $InitReq $Output
                        }
                        # Determine PSFalcon command, execute and capture result
                        $Cmd = @{ Command = $Command }
                        if ($Argument) { $Cmd['Argument'] = $Argument }
                        if (($Output | Measure-Object).Count -gt 1) { $Cmd['Timeout'] = $Timeout }
                        if ($QueueOffline -ne $true) { $Cmd['Wait'] = $true }
                        $Invoke = Get-RtrCommand $Command
                        $PSCmdlet.WriteVerbose(('[Invoke-FalconRtr]','Submitting',"'$($Command,
                            $Argument -join ' ')'" -join ' '))
                        $CmdReq = $InitReq | & $Invoke @Cmd
                        Stop-RtrUpdate $JobId
                        if ($CmdReq) {
                            $Output = @(Get-RtrResult $CmdReq $Output).foreach{
                                # Clear 'stdout' for batch 'get' requests
                                if ($_.stdout -and $_.batch_get_cmd_req_id) { $_.stdout = $null }
                                if ($_.stdout -and $Command -eq 'runscript') {
                                    # Attempt to convert 'stdout' from Json for 'runscript'
                                    [object[]]$StdOut = try { $_.stdout | ConvertFrom-Json } catch { $null }
                                    if ($StdOut) { $_.stdout = $StdOut }
                                }
                                $_
                            }
                        }
                        $Output
                    }
                } catch {
                    $PSCmdlet.WriteError($_)
                }
            }
        }
    }
}
Register-ArgumentCompleter -CommandName Invoke-FalconRtr -ParameterName Command -ScriptBlock {
    Get-RtrCommand | Sort-Object }