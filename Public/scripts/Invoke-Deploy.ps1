function Invoke-Deploy {
    <#
    .SYNOPSIS
        Deploy and run an executable using Real-time Response
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'scripts/InvokeDeploy')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('scripts/InvokeDeploy')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Max = 500
        $FileDateTime = Get-Date -Format FileDateTime
        $OutputFile = "$pwd\FalconDeploy_$FileDateTime.csv"
        if ($PSBoundParameters.Debug -eq $true) {
            $LogFile = "$pwd\FalconDeploy_$FileDateTime.log"
        }
        $FilePath = $Dynamic.Path.Value
        $Filename = "$([System.IO.Path]::GetFileName($FilePath))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($FilePath))"
        function Add-Field ($Object, $Name, $Value) {
            $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name, $Value)))
        }
        function Write-Result ($Object, $Step) {
            foreach ($Result in @($Object.resources, $Object.combined.resources)) {
                foreach ($Item in $Result.psobject.properties.Value) {
                    $Output = [PSCustomObject] @{
                        batch_id = if ($Object.batch_id) {
                            $Object.batch_id
                        }
                        elseif ($Session.batch_id) {
                            $Session.batch_id
                        }
                        else {
                            $null
                        }
                    }
                    (($Item | Select-Object aid, session_id, task_id, complete, stdout,
                        stderr, errors, offline_queued).psobject.properties).foreach{
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
                        Add-Field -Object $Output -Name $Name -Value $Value
                    }
                    Add-Field -Object $Output -Name 'deployment_step' -Value $Step
                    $Output | Export-Csv $OutputFile -Append -NoTypeInformation -Force
                }
            }
        }
        function Write-Log ($Value) {
            Write-Host "[$($Falcon.Rfc3339(0))] $Value"
        }
        if (-not $PSBoundParameters.Help -and $FilePath) {
            try {
                Write-Log "Checking cloud for existing file..."
                $CloudFile = foreach ($Item in (
                        (Get-FalconPutFile -Filter "name:'$Filename'" -Detailed).resources |
                            Select-Object id, name, created_timestamp, modified_timestamp, sha256)) {
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
                        Write-Log "Hash match: $($LocalFile.sha256)"
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
                            Write-Log "Proceeding with $($CloudFile.id)..."
                        }
                        else {
                            $RemovePut = Remove-FalconPutFile -FileId $CloudFile.id
                            if ($RemovePut.meta.writes.resources_affected -ne 1) {
                                throw "$($RemovePut.errors.code): $($RemovePut.errors.message)"
                            }
                            Write-Log "Removed cloud file $($CloudFile.id)"
                        }
                    }
                }
            }
            catch {
                Write-Error "$($_.Exception.Message)"
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
                if (($RemovePut.meta.writes.resources_affected -eq 1) -or (-not $CloudFile)) {
                    Write-Log "Uploading $Filename..."
                    $Param = @{
                        Path        = $FilePath
                        Name        = $Filename
                        Description = "$ProcessName"
                        Comment     = "psfalcon: Invoke-FalconDeploy"
                    }
                    $AddPut = Send-FalconPutFile @Param
                    if ($AddPut.meta.writes.resources_affected -ne 1) {
                        throw "$($AddPut.errors.code): $($AddPut.errors.message)"
                    }
                }
                for ($i = 0; $i -lt ($PSBoundParameters.HostIds).count; $i += $Max) {
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
                    if (-not $Session.batch_id) {
                        throw "$($Session.errors.code): $($Session.errors.message)"
                    }
                    else {
                        Write-Result $Session "session_start"
                        $SessionHosts = ($Session.resources.psobject.properties.Value |
                            Where-Object { ($_.complete -eq $true) -or ($_.offline_queued -eq $true) }).aid
                    }
                    if ($SessionHosts) {
                        Write-Log "Pushing $Filename to $($SessionHosts.count) host(s)..."
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
                        if (-not $CmdPut.combined.resources) {
                            throw "$($CmdPut.errors.code): $($CmdPut.errors.message)"
                        }
                        else {
                            Write-Result $CmdPut "put_file"
                            $PutHosts = ($CmdPut.combined.resources.psobject.properties.Value |
                                Where-Object { ($_.stdout -eq 'Operation completed successfully.') -or
                                ($_.offline_queued -eq $true) }).aid
                        }
                    }
                    if ($PutHosts) {
                        Write-Log "Starting $Filename on $($PutHosts.count) host(s)..."
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
                        if (-not $CmdRun.combined.resources) {
                            throw "$($CmdRun.errors.code): $($CmdRun.errors.message)"
                        }
                        else {
                            Write-Result $CmdRun "run_file"
                        }
                    }
                    if ($PSBoundParameters.Debug -eq $true) {
                        foreach ($Item in @('RemovePut', 'AddPut', 'Session', 'CmdPut', 'CmdRun')) {
                            if (Get-Variable $Item -ErrorAction SilentlyContinue) {
                                "$($Item):`n $((Get-Variable $Item).Value | ConvertTo-Json -Depth 8)`n" |
                                    Out-File $LogFile -Append
                            }
                        }
                    }
                }
            }
            catch {
                Write-Error "$($_.Exception.Message)"
            }
            finally {
                foreach ($Item in @($LogFile, $OutputFile)) {
                    if ($Item -and (Test-Path $Item)) {
                        Get-ChildItem $Item | Out-Host
                    }
                }
            }
        }
    }
}