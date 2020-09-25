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
        function Write-Log ($Value) {
            Write-Verbose "[Invoke-FalconForensics] $Value"
        }
        try {
            # Capture filename from input path
            $Filename = "$([System.IO.Path]::GetFileName($Dynamic.Path.Value))"
            $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($Dynamic.Path.Value))"

            # Check for existing version in 'Put Files'
            $CloudFile = ((Get-FalconPutFile -Filter "name:'$Filename'" -Detailed).resources |
            Select-Object id, name, created_timestamp, modified_timestamp, sha256).foreach{
                [PSCustomObject] @{
                    id = $_.id
                    Name = $_.name
                    Created = [datetime] $_.created_timestamp
                    Modified = [datetime] $_.modified_timestamp
                    SHA256 = $_.sha256
                }
            }
            if ($CloudFile) {
                Write-Log "Found remote file $($CloudFile.id)"

                # Capture detail about local file to compare with 'Put Files'
                $LocalFile = (Get-ChildItem $Dynamic.Path.Value |
                Select-Object CreationTime, Name, LastWriteTime).foreach{
                    [PSCustomObject] @{
                        Name = $_.name
                        Created = [datetime] $_.CreationTime
                        Modified = [datetime] $_.LastWriteTime
                        SHA256 = ((Get-FileHash -Algorithm SHA256 -Path $Dynamic.Path.Value).Hash).ToLower()
                    }
                }
                if ($LocalFile.SHA256 -eq $CloudFile.SHA256) {
                    Write-Log "Hash match between local and remote file"
                } else {
                    # Prompt user to choose between local file and 'Put File'
                    (@('CloudFile', 'LocalFile')).foreach{
                        Write-Host "[$($_ -replace 'File', $null)]"
                        (Get-Variable $_).Value | Select-Object Name, Created, Modified, SHA256 |
                        Format-List | Out-Host
                    }
                    $FileChoice = $host.UI.PromptForChoice(
                    "$Filename exists in your 'Put Files'. Use the existing version?", $null,
                    [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No"), 0)

                    if ($FileChoice -eq 0) {
                        Write-Log "User answered 'Yes' to using $($CloudFile.id)"
                    } else {
                        Write-Log "User answered 'No' to using $($CloudFile.id)"

                        # Remove existing 'Put File'
                        $RemovePut = Remove-FalconPutFile -FileId $CloudFile.id

                        if ($RemovePut.meta.writes.resources_affected -ne 1) {
                            throw "$($RemovePut.errors.code): $($RemovePut.errors.message)"
                        }
                        Write-Log "Removed file $($CloudFile.id)"
                    }
                }
            }
        } catch {
            Write-Error "$($_.Exception.Message)"
        }
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            try {
                if (($RemovePut.meta.writes.resources_affected -eq 1) -or (-not $CloudFile)) {
                    # Upload local file to 'Put Files'
                    $Param = @{
                        Path = $Dynamic.Path.Value
                        Name = $Filename
                        Description = "Falcon Forensics Collector"
                        Comment = "Uploaded using PSFalcon: Invoke-FalconForensics"
                    }
                    $AddPut = Send-FalconPutFile @Param

                    if ($AddPut.meta.writes.resources_affected -ne 1) {
                        throw "$($RemovePut.errors.code): $($RemovePut.errors.message)"
                    }
                }
                # Start Real-time Response session
                $Param = @{
                    HostIds = $Dynamic.HostIds.Value
                }
                if ($QueueOffline) {
                    $Param['QueueOffline'] = $QueueOffline
                }
                $Session = Start-FalconSession @Param

                if (-not $Session.batch_id) {
                    throw "$($Session.errors.code): $($Session.errors.message)"
                }
                Write-Log "Started batch with $($Session.combined.resources.count) host(s)"

                # PowerShell command to check for FFC status
                $ProcessStatus = ("if (Get-Process | Where-Object { `$_.ProcessName -eq $($ProcessName) })" +
                " { Write-Host `"RUNNING`" } else { Write-Output `"NOT_RUNNING`" }")

                # Verify FFC is not currently running
                $Param = @{
                    BatchId = $Session.batch_id
                    Command = 'runscript'
                    Arguments = "-Raw='$ProcessStatus'"
                }
                $CmdScript = Invoke-FalconAdminCommand @Param

                if (-not $CmdScript.combined.resources) {
                    throw "$($CmdScript.errors.code): $($CmdScript.errors.message)"
                }
                $ProcessOK = ($CmdScript.combined.resources.psobject.properties.value |
                Where-Object { $_.stdout -eq 'NOT_RUNNING' }).aid

                Write-Log "Changing directory for $($ProcessOK.count) host(s)"

                # Change directories to \Program Files\CrowdStrike
                $Param = @{
                    BatchId = $Session.batch_id
                    Command = 'cd'
                    Arguments = '"\Program Files\CrowdStrike"'
                    OptionalHostIds = $ProcessOK
                }
                $CmdPath = Invoke-FalconAdminCommand @Param

                if (-not $CmdPath.combined.resources) {
                    throw "$($CmdPath.errors.code): $($CmdPath.errors.message)"
                }
                $DirectoryOK = ($CmdPath.combined.resources.psobject.properties.value |
                Where-Object { $_.complete -eq $true }).aid

                Write-Log "Putting $Filename on $($DirectoryOK.count) host(s)"

                # Push FFC to target hosts
                $Param = @{
                    BatchId = $Session.batch_id
                    Command = 'put'
                    Arguments = "$Filename"
                    OptionalHostIds = $DirectoryOK
                }
                $CmdPut = Invoke-FalconAdminCommand @Param

                if (-not $CmdPut.combined.resources) {
                    throw "$($CmdPut.errors.code): $($CmdPut.errors.message)"
                }
                $PutOK = ($CmdPut.combined.resources.psobject.properties.value |
                Where-Object { $_.complete -eq $true }).aid

                Write-Log "Starting $Filename on $($PutOK.count) host(s)"

                # Run FFC
                $Param = @{
                    BatchId = $Session.batch_id
                    Command = 'run'
                    Arguments = "$Filename"
                    OptionalHostIds = $PutOK
                }
                Invoke-FalconAdminCommand @Param
            } catch {
                Write-Error "$($_.Exception.Message)"
            }
        }
    }
}