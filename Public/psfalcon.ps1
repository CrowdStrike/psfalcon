function Export-FalconReport {
<#
.Synopsis
Format a response object and output to CSV
.Parameter Path
Destination path
.Parameter Object
A result object to format (can be passed via pipeline)
#>
param()
begin {}
process {}
end {}
}
function Export-FalconConfig {
<#
.Synopsis
Create an archive containing exported Falcon configuration files
.Description
Uses various PSFalcon commands to gather and export Groups, Policies and Exclusions as a collection of Json files
within a zip archive. The exported files can be used with 'Import-FalconConfig' to restore configurations to your
existing CID, or create them in another CID.
.Parameter Items
Items to export from your current CID; leave blank to export all available items
.Example
PS>Export-FalconConfig

Creates '.\FalconConfig_<FileDate>.zip' with all available configuration files.
.Example
PS>Export-FalconConfig -Items HostGroup, FirewallGroup, FirewallPolicy

Creates '.\FalconConfig_<FileDate>.zip' with HostGroup, FirewallGroup (including Firewall Rules),
and FirewallPolicy configuration files.
#>
    [CmdletBinding(DefaultParameterSetName = 'ExportItems')]
    param(
        [Parameter(ParameterSetName = 'ExportItems', Position = 1)]
        [ValidateSet('HostGroup', 'IoaGroup', 'FirewallGroup', 'DeviceControlPolicy', 'FirewallPolicy',
            'PreventionPolicy', 'ResponsePolicy', 'SensorUpdatePolicy', 'Ioc', 'IoaExclusion', 'MlExclusion',
            'SvExclusion')]
        [array] $Items
    )
    begin {
        function Get-ItemContent ($Item) {
            # Request content for provided 'Item'
            Write-Host "Exporting '$Item'..."
            $ItemFile = Join-Path -Path $Location -ChildPath "$Item.json"
            $Param = @{
                Detailed = $true
                All = $true
            }
            $FileContent = if ($Item -match '^(DeviceControl|Firewall|Prevention|Response|SensorUpdate)Policy$') {
                # Create policy exports in 'platform_name' order to retain precedence
                @('Windows','Mac','Linux').foreach{
                    & "Get-Falcon$($Item)" @Param -Filter "platform_name:'$_'+name:!'platform_default'" 2>$null
                }
            } else {
                & "Get-Falcon$($Item)" @Param 2>$null
            }
            if ($FileContent -and $Item -eq 'FirewallPolicy') {
                # Export firewall settings
                Write-Host "Exporting 'FirewallSetting'..."
                $Settings = Get-FalconFirewallSetting -Ids $FileContent.id 2>$null
                foreach ($Result in $Settings) {
                    ($FileContent | Where-Object { $_.id -eq $Result.policy_id }).PSObject.Properties.Add(
                        (New-Object PSNoteProperty('settings', $Result)))
                }
            }
            if ($FileContent) {
                # Export results to json file and output created file name
                ConvertTo-Json -InputObject @( $FileContent ) -Depth 16 | Out-File -FilePath $ItemFile -Append
                $ItemFile
            }
        }
        # Get current location
        $Location = [Environment]::CurrentDirectory
        $Export = if ($PSBoundParameters.Items) {
            # Use specified items
            $PSBoundParameters.Items
        } else {
            # Use items in 'ValidateSet' when not provided
            (Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({ $_.Name -eq
            'ExportItems' }).Parameters.Where({ $_.Name -eq 'Items' }).Attributes.ValidValues
        }
        # Set output archive path
        $ArchiveFile = Join-Path $Location -ChildPath "FalconConfig_$(Get-Date -Format FileDate).zip"
    }
    process {
        if (Test-Path $ArchiveFile) {
            throw "An item with the specified name $ArchiveFile already exists."
        }
        [array] $Export += switch ($Export) {
            { $_ -match '^((Ioa|Ml|Sv)Exclusion|Ioc)$' -and $Export -notcontains 'HostGroup' } {
                # Force 'HostGroup' when exporting Exclusions or IOCs
                'HostGroup'
            }
            { $_ -contains 'FirewallGroup' } {
                # Force 'FirewallRule' when exporting 'FirewallGroup'
                'FirewallRule'
            }
        }
        $JsonFiles = foreach ($Item in $Export) {
            # Retrieve results, export to Json and capture file name
            ,(Get-ItemContent -Item $Item)
        }
        if ($JsonFiles) {
            # Archive Json exports with content
            $Param = @{
                Path = (Get-ChildItem | Where-Object { $JsonFiles -contains $_.FullName -and
                    $_.Length -gt 0 }).FullName
                DestinationPath = $ArchiveFile
            }
            Compress-Archive @Param
            if (Test-Path $ArchiveFile) {
                # Display created archive
                Get-ChildItem $ArchiveFile
            }
            if (Test-Path $JsonFiles) {
                # Remove Json files when archived
                Remove-Item -Path $JsonFiles -Force
            }
        }
    }
}
function Find-FalconDuplicate {
<#
.Synopsis
Find duplicate hosts within your Falcon environment
.Description
If the 'Hosts' parameter is not provided, all Host information will be retrieved. An error will be displayed if
required fields 'cid', 'device_id', 'first_seen', 'last_seen', 'hostname' and any defined 'filter' value are
not present.

Hosts are grouped by 'cid', 'hostname' and any defined 'filter' value, then sorted by 'last_seen' time. Any
result other than the one with the most recent 'last_seen' time is considered a duplicate host and is returned
within the output.
.Parameter Hosts
Array of 'Get-FalconHost -Detailed' results
.Parameter Filter
Property to determine duplicate Host(s) in addition to 'hostname'
.Role
devices:write
.Example
PS> Find-FalconDuplicate

Retrieve a list of all hosts and output potential duplicates using the 'hostname' field.
.Example
PS>$Duplicates = Find-FalconDuplicate -Filter 'mac_address'
PS>Invoke-FalconHostAction -Name hide_host -Ids $Duplicates.device_id

Find duplicate Hosts using 'hostname' and 'mac_address', then hide results within the Falcon console.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [array] $Hosts,

        [Parameter(Position = 2)]
        [ValidateSet('external_ip', 'local_ip', 'mac_address', 'os_version', 'platform_name', 'serial_number')]
        [string] $Filter
    )
    begin {
        function Group-Selection ($Object, $GroupBy) {
            ($Object | Group-Object $GroupBy).Where({ $_.Count -gt 1 -and $_.Name }).foreach{
                $_.Group | Sort-Object last_seen | Select-Object -First (($_.Count) - 1)
            }
        }
        # Comparison criteria and required properties for host results
        $Criteria = @('cid', 'hostname')
        $Required = @('cid', 'device_id', 'first_seen', 'last_seen', 'hostname')
        if ($PSBoundParameters.Filter) {
            $Criteria += $PSBoundParameters.Filter
            $Required += $PSBoundParameters.Filter
        }
        # Create filter for excluding results with empty $Criteria values
        $FilterScript = { (($Criteria).foreach{ "`$_.$($_)" }) -join ' -and ' }
    }
    process {
        $HostArray = if (!$PSBoundParameters.Hosts) {
            # Retreive Host details
            Get-FalconHost -Detailed -All
        } else {
            $PSBoundParameters.Hosts
        }
        ($Required).foreach{
            if (($HostArray | Get-Member -MemberType NoteProperty).Name -notcontains $_) {
                # Verify required properties are present
                throw "Missing required property '$_'."
            }
        }
        # Group, sort and output result
        $Param = @{
            Object  = $HostArray | Select-Object $Required | Where-Object -FilterScript $FilterScript
            GroupBy = $Criteria
        }
        $Output = Group-Selection @Param
    }
    end {
        if ($Output) {
            $Output
        } else {
            Write-Warning "No duplicates found."
        }
    }
}
function Get-FalconQueue {
<#
.Synopsis
Create a report of Real-time Response commands in the offline queue
.Description
Creates a CSV of pending Real-time Response commands and their related session information. Sessions within the
offline queue expire 7 days after creation by default. Sessions can have additional commands appended to them
to extend their expiration time.
.Parameter Days
Days worth of results to retrieve [default: 7]
.Example
PS>Get-FalconQueue -Days 14

Output pending Real-time Response sessions in the offline queue that were created within the last 14 days. Any
sessions that expired at the end of the default 7 day period will not be displayed.
.Role
real-time-response-admin:write
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [int] $Days
    )
    begin {
        $Days = if ($PSBoundParameters.Days) {
            $PSBoundParameters.Days
        } else {
            7
        }
        $OutputFile = Join-Path -Path ([Environment]::CurrentDirectory) -ChildPath "FalconQueue_$(
            Get-Date -Format FileDateTime).csv"
        $Filter = "(deleted_at:null+commands_queued:1),(created_at:>'last $Days days'+commands_queued:1)"
    }
    process {
        try {
            Get-FalconSession -Filter $Filter -All -Verbose | ForEach-Object {
                Get-FalconSession -Ids $_ -Queue -Verbose | ForEach-Object {
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
            throw $_
        } finally {
            if (Test-Path $OutputFile) {
                Get-ChildItem $OutputFile | Out-Host
            }
        }
    }
}
function Invoke-FalconDeploy {
<#
.Synopsis
Deploy and run an executable using Real-time Response
.Description
'Put' files will be checked for identical file names, and if any are found, the Sha256 hash values will be
compared between your local and cloud files. If they are different, a prompt will appear asking which file to use.

If the file is not present in 'Put' files, it will be uploaded.

Once uploaded, a Real-time Response session will be started for the designated Host(s), the file will be 'put'
into the root drive, and 'run' if successfully transferred.

Details of each step will be output to a CSV file in the current directory.
.Parameter Path
Path to local file
.Parameter Arguments
Arguments to include when running the executable
.Parameter Timeout
Length of time to wait for a result, in seconds
.Parameter QueueOffline
Add non-responsive Hosts to the offline queue
.Parameter HostIds
Host identifier(s)
.Parameter GroupId
Host Group identifier
.Role
real-time-response-admin:write
.Example
PS>Invoke-FalconDeploy -Path C:\files\example.exe -HostIds <id>, <id>

The file 'example.exe' will be 'put' and 'run' on <id> and <id>.
#>
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName = 'HostIds')]
    param(
        [Parameter(ParameterSetName = 'HostIds', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'GroupId', Mandatory = $true, Position = 1)]
        [ValidateScript({
            if (Test-Path $_) {
                $true
            } else {
                throw "Cannot find path '$_' because it does not exist."
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
        $OutputFile = Join-Path -Path ([Environment]::CurrentDirectory) -ChildPath "FalconDeploy_$(
            Get-Date -Format FileDateTime).csv"
        $FilePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
        $Filename = "$([System.IO.Path]::GetFileName($FilePath))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($FilePath))"
        [array] $HostArray = if ($PSBoundParameters.GroupId) {
            try {
                # Find Host Group member identifiers
                Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId
            } catch {
                throw $_
            }
        } else {
            # Use provided Host identifiers
            $PSBoundParameters.HostIds
        }
        if ($HostArray) {
            try {
                Write-Host "Checking cloud for existing file..."
                $CloudFile = Get-FalconPutFile -Filter "name:['$Filename']" -Detailed | Select-Object $PutFields |
                ForEach-Object {
                    [PSCustomObject] @{
                        id                 = $_.id
                        name               = $_.name
                        created_timestamp  = [datetime] $_.created_timestamp
                        modified_timestamp = [datetime] $_.modified_timestamp
                        sha256             = $_.sha256
                    }
                }
                $LocalFile = Get-ChildItem $FilePath | Select-Object CreationTime, Name, LastWriteTime |
                ForEach-Object {
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
                        HostIds = $HostArray[$i..($i + 499)]
                    }
                    switch -Regex ($PSBoundParameters.Keys) {
                        '(QueueOffline|Timeout)' { $Param[$_] = $PSBoundParameters.$_ }
                    }
                    $Session = Start-FalconSession @Param
                    $SessionHosts = if ($Session) {
                        # Output result to CSV and return list of successful 'session_start' hosts
                        Write-RtrResult -Object $Session.hosts -Step 'session_start' -BatchId $Session.batch_id
                        ($Session.hosts | Where-Object { $_.complete -eq $true -or
                            $_.offline_queued -eq $true }).aid
                    }
                    $PutHosts = if ($SessionHosts) {
                        # Invoke 'put' on successful hosts
                        Write-Host "Sending $Filename to $(($SessionHosts | Measure-Object).Count) host(s)..."
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
                            # Output result to CSV and return list of successful 'put_file' hosts
                            Write-RtrResult -Object $CmdPut -Step 'put_file' -BatchId $Session.batch_id
                            ($CmdPut | Where-Object { $_.stdout -eq 'Operation completed successfully.' -or
                                $_.offline_queued -eq $true }).aid
                        }
                    }
                    if ($PutHosts) {
                        # Invoke 'run'
                        Write-Host "Starting $Filename on $(($PutHosts | Measure-Object).Count) host(s)..."
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
                            # Output result to CSV
                            Write-RtrResult -Object $CmdRun -Step 'run_file' -BatchId $Session.batch_id
                        }
                    }
                }
            } catch {
                throw $_
            } finally {
                if (Test-Path $OutputFile) {
                    Get-ChildItem $OutputFile | Out-Host
                }
            }
        }
    }
}
function Invoke-FalconRTR {
<#
.Synopsis
Start Real-time Response session(s), execute a command and output the result(s)
.Parameter Command
Real-time Response command
.Parameter Arguments
Arguments to include with the command
.Parameter Timeout
Length of time to wait for a result, in seconds
.Parameter QueueOffline
Add non-responsive Hosts to the offline queue
.Parameter HostIds
Host identifier(s)
.Parameter GroupId
Host Group identifier
.Role
real-time-response-admin:write
.Example
PS>Invoke-FalconRTR runscript "-CloudFile='HelloWorld'" -HostIds <id>, <id>

The command 'runscript' will be used to execute the previously-created Response Script called 'HelloWorld'
on <id> and <id>.
#>
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
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id', $null)))
                }
                if ($PSBoundParameters.GroupId) {
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id', $null)))
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
        $HostArray = if ($PSBoundParameters.GroupId) {
            try {
                # Find Host Group member identifiers
                Get-FalconHostGroupMember -Id $PSBoundParameters.GroupId
            } catch {
                throw $_
            }
        } else {
            # Use provided Host identifiers
            $PSBoundParameters.HostIds
        }
        try {
            for ($i = 0; $i -lt ($HostArray | Measure-Object).Count; $i += 500) {
                # Create baseline output and define request parameters
                [array] $Group = Initialize-Output $HostArray[$i..($i + 499)]
                $InitParam = @{
                    HostIds = $Group.aid
                }
                if ($PSBoundParameters.QueueOffline) {
                    $InitParam['QueueOffline'] = $PSBoundParameters.QueueOffline
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
                # Request session and capture initialization result
                $InitRequest = Start-FalconSession @InitParam
                $InitResult = Get-RtrResult -Object $InitRequest.hosts -Output $Group
                if ($InitRequest.batch_id) {
                    $InitResult | Where-Object { $_.session_id } | ForEach-Object {
                        # Add batch_id to initialized sessions
                        $_.batch_id = $InitRequest.batch_id
                    }
                    # Perform command request and capture result
                    $CmdRequest = & $InvokeCmd @CmdParam -BatchId $InitRequest.batch_id
                    $CmdResult = Get-RtrResult -Object $CmdRequest -Output $InitResult
                    if ($InvokeCmd -eq 'Invoke-FalconBatchGet' -and $CmdRequest.batch_get_cmd_req_id) {
                        $CmdResult | Where-Object { $_.session_id -and $_.complete -eq $true } | ForEach-Object {
                            # Add 'batch_get_cmd_req_id' and remove 'stdout' from session
                            $_.PSObject.Properties.Add((New-Object PSNoteProperty('batch_get_cmd_req_id',
                                $CmdRequest.batch_get_cmd_req_id)))
                            $_.stdout = $null
                        }
                    }
                    $CmdResult
                } else {
                    $InitResult
                }
            }
        } catch {
            throw $_
        }
    }
}
function Show-FalconMap {
<#
.Synopsis
Use your default browser to display indicators on the Falcon X Indicator Map. Invalid indicator values are ignored.
.Parameter Indicators
Real-time Response command
.Example
PS>Show-FalconMap -Indicators 93.184.216.34, example.com, <sha256_hash>

The default browser will open and the indicator map will be displayed for "ip:93.184.216.34", "domain:example.com",
and "hash:<sha256_hash>".
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [array] $Indicators
    )
    begin {
        $FalconUI = "$($Script:Falcon.Hostname -replace 'api', 'falcon')"
        $Inputs = ($PSBoundParameters.Indicators).foreach{
            $Type = Confirm-String $_
            $Value = if ($Type -match '^(domain|md5|sha256)$') {
                $_.ToLower()
            } else {
                $_
            }
            if ($Type) {
                "$($Type):'$Value'"
            }
        }
    }
    process {
        Start-Process "$($FalconUI)/intelligence/graph?indicators=$($Inputs -join ',')"
    }
}
function Show-FalconModule {
<#
.Synopsis
Display information about your PSFalcon installation.
.Description
Outputs an object containing module, user and system version information that is helpful for diagnosing problems
with the PSFalcon module.
#>
    [CmdletBinding()]
    param()
    begin {
        $Parent = Split-Path -Path $Script:Falcon.Api.Path($PSScriptRoot) -Parent
    }
    process {
        if (Test-Path "$Parent\PSFalcon.psd1") {
            $Module = Import-PowerShellDataFile $Parent\PSFalcon.psd1
            [PSCustomObject] @{
                ModuleVersion    = "v$($Module.ModuleVersion) {$($Module.GUID)}"
                ModulePath       = $Parent
                UserHome         = $HOME
                UserPSModulePath = ($env:PSModulePath -split ';') -join ', '
                UserSystem       = ("PowerShell $($PSVersionTable.PSEdition): v$($PSVersionTable.PSVersion)" +
                    " [$($PSVersionTable.OS)]")
                UserAgent        = $Script:Falcon.Api.Client.DefaultRequestHeaders.UserAgent.ToString()
            }
        } else {
            throw "Cannot find 'PSFalcon.psd1'"
        }
    }
}