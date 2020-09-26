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
        # Capture filename and process name from input
        $Filename = "$([System.IO.Path]::GetFileName($Dynamic.Path.Value))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($Dynamic.Path.Value))"

        # Output CSV filename
        $OutputFile = "$pwd\Invoke-FalconForensics_$(Get-Date -Format FileDateTime).csv"

        if ($PSBoundParameters.Debug -eq $true) {
            # Filename for debug logging
            $LogFile = "$pwd\Invoke-FalconForensics_$(Get-Date -Format FileDateTime).log"
        }
        # Create output objects for each identifier
        $Output = @($HostIds).foreach{
            [PSCustomObject] @{
                aid = $_
            }
        }
        function Add-Field ($Object, $Name, $Value) {
            # Add NoteProperty to PSCustomObject
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        function Get-Result ($Object) {
            @($Object.resources, $Object.combined.resources).foreach{
                foreach ($Item in $_.psobject.properties.value) {
                    $Target = ($Output | Where-Object { $_.aid -eq $Item.aid })

                    if ($Object.batch_id) {
                        Add-Field $Target 'batch_id' $Object.batch_id
                    }
                    (($Item | Select-Object session_id, task_id, complete, stdout, stderr, errors,
                    offline_queued).psobject.properties).foreach{
                        $Value = if (($_.name -eq 'errors') -and $_.value) {
                            "$($_.value.code): $($_.value.message)"
                        } else {
                            $_.value
                        }
                        Add-Field $Target $_.name $Value
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
            $CloudFile = ((Get-FalconPutFile -Filter "name:'$Filename'" -Detailed).resources |
            Select-Object id, name, created_timestamp, modified_timestamp, sha256).foreach{
                # Capture relevant fields into hashtable
                [ordered] @{
                    id = $_.id
                    name = $_.name
                    created_timestamp = [datetime] $_.created_timestamp
                    modified_timestamp = [datetime] $_.modified_timestamp
                    sha256 = $_.sha256
                }
            }
            if ($CloudFile) {
                # Capture detail about local file to compare with cloud file
                $LocalFile = (Get-ChildItem $Dynamic.Path.Value |
                Select-Object CreationTime, Name, LastWriteTime).foreach{
                    # Capture relevant fields into hashtable
                    [ordered] @{
                        name = $_.name
                        created_timestamp = [datetime] $_.CreationTime
                        modified_timestamp = [datetime] $_.LastWriteTime
                        sha256 = ((Get-FileHash -Algorithm SHA256 -Path $Dynamic.Path.Value).Hash).ToLower()
                    }
                }
                if ($LocalFile.sha256 -eq $CloudFile.sha256) {
                    Write-Log "Hash match: $($LocalFile.sha256)"
                } else {
                    # Prompt user to choose between local file and cloud file
                    (@('CloudFile', 'LocalFile')).foreach{
                        Write-Host "[$($_ -replace 'File', $null)]"

                        (Get-Variable $_).Value | Select-Object name, created_timestamp,
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
                # Start Real-time Response session
                $Param = @{
                    HostIds = $Dynamic.HostIds.Value
                }
                switch ($PSBoundParameters.Keys) {
                    'QueueOffline' { $Param['QueueOffline'] = $QueueOffline }
                    'Timeout' { $Param['Timeout'] = $Timeout }
                }
                $Session = Start-FalconSession @Param

                if (-not $Session.batch_id) {
                    # Error if session fails
                    throw "$($Session.errors.code): $($Session.errors.message)"
                } else {
                    # Capture results
                    Get-Result $Session

                    # Capture identifiers for hosts in batch session
                    $SessionHosts = ($Session.resources.psobject.properties.value |
                    Where-Object { $_.complete -eq $true }).aid
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
                    switch ($PSBoundParameters.Keys) {
                        'QueueOffline' { $Param['QueueOffline'] = $QueueOffline }
                        'Timeout' { $Param['Timeout'] = $Timeout }
                    }
                    $CmdScript = Invoke-FalconAdminCommand @Param

                    if (-not $CmdScript.combined.resources) {
                        # Error if 'runscript' command fails
                        throw "$($CmdScript.errors.code): $($CmdScript.errors.message)"
                    } else {
                        # Capture results
                        Get-Result $CmdScript

                         # Capture identifiers for hosts that do not have a running FFC process
                        $ScriptHosts = ($CmdScript.combined.resources.psobject.properties.value |
                        Where-Object {($_.stdout -ne 'IN_PROGRESS') -and ((-not $_.stderr) -or ($_.errors))}).aid
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
                    switch ($PSBoundParameters.Keys) {
                        'QueueOffline' { $Param['QueueOffline'] = $QueueOffline }
                        'Timeout' { $Param['Timeout'] = $Timeout }
                    }
                    $CmdPut = Invoke-FalconAdminCommand @Param

                    if (-not $CmdPut.combined.resources) {
                        # Error if 'put' command fails
                        throw "$($CmdPut.errors.code): $($CmdPut.errors.message)"
                    } else {
                        # Capture results
                        Get-Result $CmdPut

                        # Capture identifiers for hosts that had a successful 'put'
                        $PutHosts = ($CmdPut.combined.resources.psobject.properties.value |
                        Where-Object { $_.complete -eq $true }).aid
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
                    switch ($PSBoundParameters.Keys) {
                        'QueueOffline' { $Param['QueueOffline'] = $QueueOffline }
                        'Timeout' { $Param['Timeout'] = $Timeout }
                    }
                    $CmdRun = Invoke-FalconAdminCommand @Param

                    if (-not $CmdRun.combined.resources) {
                        # Error if 'run' command fails
                        throw "$($CmdRun.errors.code): $($CmdRun.errors.message)"
                    }
                }
            } catch {
                # Output error
                Write-Error "$($_.Exception.Message)"
            } finally {
                if ($PSBoundParameters.Debug -eq $true) {
                    @('RemovePut', 'AddPut', 'Session', 'CmdScript', 'CmdPut', 'CmdRun').foreach{
                        # Capture full responses in $LogFile
                        if (Get-Variable $_ -ErrorAction SilentlyContinue) {
                            "$($_):`n $((Get-Variable $_).Value | ConvertTo-Json -Depth 8)`n" |
                            Out-File $LogFile -Append
                        }
                    }
                }
                # Output results to CSV
                $Output | Export-Csv $OutputFile -Append -NoTypeInformation -Force

                @($LogFile, $OutputFile).foreach{
                    if ($_ -and (Test-Path $_)) {
                        # Display created file(s)
                        Get-ChildItem $_ | Out-Host
                    }
                }
            }
        }
    }
}