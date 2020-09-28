function Invoke-Forensics {
<#
.SYNOPSIS
    Deploy and execute Falcon Forensics using Real-time Response
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'InvokeForensics')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('InvokeForensics')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        # Maximum number of hosts in each request group
        $Max = 500

        # Output CSV filename
        $OutputFile = "$pwd\Invoke-FalconForensics_$(Get-Date -Format FileDateTime).csv"

        if ($PSBoundParameters.Debug -eq $true) {
            # Filename for debug logging
            $LogFile = "$pwd\Invoke-FalconForensics_$(Get-Date -Format FileDateTime).log"
        }
        # Capture filename and process name from input
        $Filename = "$([System.IO.Path]::GetFileName($Dynamic.Path.Value))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($Dynamic.Path.Value))"

        function Add-Field ($Object, $Name, $Value) {
            # Add NoteProperty to PSCustomObject
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        function Get-Result ($Object, $Output) {
            foreach ($Result in @($Object.resources, $Object.combined.resources)) {
                foreach ($Item in $Result.psobject.properties.value) {
                    $Target = ($Output | Where-Object { $_.aid -eq $Item.aid })

                    if ($Object.batch_id) {
                        Add-Field $Target 'batch_id' $Object.batch_id
                    }
                    foreach ($Property in (($Item | Select-Object session_id, task_id, complete, stdout,
                    stderr, errors, offline_queued).psobject.properties)) {
                        $Value = if (($Property.name -eq 'errors') -and $Property.value) {
                            "$($Property.value.code): $($Property.value.message)"
                        } else {
                            $Property.value
                        }
                        Add-Field $Target $Property.name $Value
                    }
                }
            }
        }
        function Write-Log ($Value) {
            # Output timestamped message to console
            Write-Host "[$($Falcon.Rfc3339(0))] $Value"
        }
        try {
            Write-Log "Checking cloud for existing file..."

            # Check for existing file in cloud
            $CloudFile = foreach ($Item in ((Get-FalconPutFile -Filter "name:'$Filename'" -Detailed).resources |
            Select-Object id, name, created_timestamp, modified_timestamp, sha256)) {
                # Capture relevant fields into hashtable
                [ordered] @{
                    id = $Item.id
                    name = $Item.name
                    created_timestamp = [datetime] $Item.created_timestamp
                    modified_timestamp = [datetime] $Item.modified_timestamp
                    sha256 = $Item.sha256
                }
            }
            if ($CloudFile) {
                # Capture detail about local file to compare with cloud file
                $LocalFile = foreach ($Item in (Get-ChildItem $Dynamic.Path.Value |
                Select-Object CreationTime, Name, LastWriteTime)) {
                    # Capture relevant fields into hashtable
                    [ordered] @{
                        name = $Item.name
                        created_timestamp = [datetime] $Item.CreationTime
                        modified_timestamp = [datetime] $Item.LastWriteTime
                        sha256 = ((Get-FileHash -Algorithm SHA256 -Path $Dynamic.Path.Value).Hash).ToLower()
                    }
                }
                if ($LocalFile.sha256 -eq $CloudFile.sha256) {
                    Write-Log "Hash match: $($LocalFile.sha256)"
                } else {
                    # Prompt user to choose between local file and cloud file
                    foreach ($Item in @('CloudFile', 'LocalFile')) {
                        Write-Host "[$($Item -replace 'File', $null)]"

                        (Get-Variable $Item).Value | Select-Object name, created_timestamp,
                        modified_timestamp, sha256 | Format-List | Out-Host
                    }
                    $FileChoice = $host.UI.PromptForChoice(
                    "$Filename exists in your 'Put Files'. Use the existing version?", $null,
                    [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No"), 0)

                    if ($FileChoice -eq 0) {
                        # Use cloud file instead of uploading
                        Write-Log "Proceeding with $($CloudFile.id)..."
                    } else {
                        # Remove existing cloud file
                        $RemovePut = Remove-FalconPutFile -FileId $CloudFile.id

                        if ($RemovePut.meta.writes.resources_affected -ne 1) {
                            # Error if remove fails
                            throw "$($RemovePut.errors.code): $($RemovePut.errors.message)"
                        }
                        Write-Log "Removed cloud file $($CloudFile.id)"
                    }
                }
            }
        } catch {
            # Output error
            Write-Error "$($_.Exception.Message)"
        }
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            try {
                if (($RemovePut.meta.writes.resources_affected -eq 1) -or (-not $CloudFile)) {
                    Write-Log "Uploading $Filename..."

                    # Upload local file to cloud
                    $Param = @{
                        Path = $Dynamic.Path.Value
                        Name = $Filename
                        Description = "Falcon Forensics Data Collection Tool"
                        Comment = "PSFalcon: Invoke-FalconForensics"
                    }
                    $AddPut = Send-FalconPutFile @Param

                    if ($AddPut.meta.writes.resources_affected -ne 1) {
                        # Error if upload fails
                        throw "$($RemovePut.errors.code): $($RemovePut.errors.message)"
                    }
                }
                for ($i = 0; $i -lt ($Dynamic.HostIds.Value).count; $i += $Max) {
                    # Create output objects for each identifier
                    $Group = foreach ($Item in $Dynamic.HostIds.Value[$i..($i + ($Max - 1))]) {
                        [PSCustomObject] @{
                            aid = $Item
                        }
                    }
                    # Start Real-time Response session
                    $Param = @{
                        HostIds = $Group.aid
                    }
                    switch -Regex ($Dynamic.Keys) {
                        '(QueueOffline|Timeout)' {
                            if ($Dynamic.$_.Value) {
                                $Param[$_] = $Dynamic.$_.Value
                            }
                        }
                    }
                    $Session = Start-FalconSession @Param

                    if (-not $Session.batch_id) {
                        # Error if session fails
                        throw "$($Session.errors.code): $($Session.errors.message)"
                    } else {
                        # Capture results
                        Get-Result $Session $Group

                        # Capture identifiers for hosts in batch session
                        $SessionHosts = ($Session.resources.psobject.properties.value |
                            Where-Object { ($_.complete -eq $true) -or ($_.offline_queued -eq $true) }).aid
                    }
                    if ($SessionHosts) {
                        Write-Log "Initiated batch session with $($SessionHosts.count) host(s)"

                        # Verify forensics collector is not currently running
                        $Param = @{
                            BatchId = $Session.batch_id
                            Command = 'runscript'
                            Arguments = "-Raw='(Get-Process | Where-Object { `$_.ProcessName -eq " +
                            "`"$ProcessName`" }).foreach{ if (`$_.path -match `"$Filename`") { `"IN_PROGRESS`"} }'"
                        }
                        if ($Dynamic.Timeout.Value) {
                            $Param['Timeout'] = $Dynamic.Timeout.Value
                        }
                        $CmdScript = Invoke-FalconAdminCommand @Param

                        if (-not $CmdScript.combined.resources) {
                            # Error if 'runscript' command fails
                            throw "$($CmdScript.errors.code): $($CmdScript.errors.message)"
                        } else {
                            # Capture results
                            Get-Result $CmdScript $Group

                            # Capture identifiers for hosts that do not have a running FFC process
                            $ScriptHosts = ($CmdScript.combined.resources.psobject.properties.value |
                                Where-Object {(($_.stdout -ne 'IN_PROGRESS') -or
                                ($_.offline_queued -eq $true)) -and ((-not $_.stderr) -or
                                ($_.errors))}).aid
                        }
                    }
                    if ($ScriptHosts) {
                        Write-Log "Putting $Filename on $($ScriptHosts.count) host(s)..."

                        # Push forensics collector to target hosts
                        $Param = @{
                            BatchId = $Session.batch_id
                            Command = 'put'
                            Arguments = "$Filename"
                            OptionalHostIds = $ScriptHosts
                        }
                        if ($Dynamic.Timeout.Value) {
                            $Param['Timeout'] = $Dynamic.Timeout.Value
                        }
                        $CmdPut = Invoke-FalconAdminCommand @Param

                        if (-not $CmdPut.combined.resources) {
                            # Error if 'put' command fails
                            throw "$($CmdPut.errors.code): $($CmdPut.errors.message)"
                        } else {
                            # Capture results
                            Get-Result $CmdPut $Group

                            # Capture identifiers for hosts that had a successful 'put'
                            $PutHosts = ($CmdPut.combined.resources.psobject.properties.value |
                            Where-Object { ($_.complete -eq $true) -or ($_.offline_queued -eq $true) }).aid
                        }
                    }
                    if ($PutHosts) {
                        Write-Log "Starting $Filename on $($PutHosts.count) host(s)..."

                        # Run forensics collector
                        $Param = @{
                            BatchId = $Session.batch_id
                            Command = 'run'
                            Arguments = "\$Filename"
                            OptionalHostIds = $PutHosts
                        }
                        if ($Dynamic.Timeout.Value) {
                            $Param['Timeout'] = $Dynamic.Timeout.Value
                        }
                        $CmdRun = Invoke-FalconAdminCommand @Param

                        if (-not $CmdRun.combined.resources) {
                            # Error if 'run' command fails
                            throw "$($CmdRun.errors.code): $($CmdRun.errors.message)"
                        }
                    }
                    if ($PSBoundParameters.Debug -eq $true) {
                        foreach ($Item in @('RemovePut', 'AddPut', 'Session', 'CmdScript', 'CmdPut', 'CmdRun')) {
                            # Capture full responses in $LogFile
                            if (Get-Variable $Item -ErrorAction SilentlyContinue) {
                                "$($Item):`n $((Get-Variable $Item).Value | ConvertTo-Json -Depth 8)`n" |
                                Out-File $LogFile -Append
                            }
                        }
                    }
                    # Output results to CSV
                    $Group | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                }
            } catch {
                # Output error
                Write-Error "$($_.Exception.Message)"
            } finally {
                # Display created file(s)
                foreach ($Item in @($LogFile, $OutputFile)) {
                    if ($Item -and (Test-Path $Item)) {
                        Get-ChildItem $Item | Out-Host
                    }
                }
            }
        }
    }
}