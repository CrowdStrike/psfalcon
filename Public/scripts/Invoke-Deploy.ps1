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
        $FilePath = $Dynamic.Path.Value
        $Filename = "$([System.IO.Path]::GetFileName($FilePath))"
        $ProcessName = "$([System.IO.Path]::GetFileNameWithoutExtension($FilePath))"
        function Write-Result ($Object, $Step, $BatchId) {
            $Output = foreach ($Aid in $Object.aid) {
                [PSCustomObject] @{
                    aid = $Aid
                    batch_id = $BatchId
                    session_id = $null
                    cloud_request_id = $null
                    complete = $false
                    stdout = $null
                    stderr = $null
                    errors = $null
                    offline_queued = $false
                    deployment_step = $Step
                }
            }
            foreach ($Result in ($Object | Select-Object aid, session_id, task_id, complete, stdout,
            stderr, errors, offline_queued)) {
                ($Result.PSObject.Properties).foreach{
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
                    ($Output | Where-Object { $_.aid -eq $Result.aid }).$Name = $Value
                }
            }
            $Output | Export-Csv $OutputFile -Append -NoTypeInformation
        }
        if (-not $PSBoundParameters.Help -and $FilePath) {
            try {
                Write-Host "Checking cloud for existing file..."
                $CloudFile = foreach ($Item in (
                Get-FalconPutFile -Filter "name:['$Filename']" -Detailed | Select-Object id, name,
                created_timestamp, modified_timestamp, sha256)) {
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
                        Write-Host "Matched hash values between local and cloud files..."
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
                            Write-Host "Proceeding with $($CloudFile.id)..."
                        }
                        else {
                            $RemovePut = Remove-FalconPutFile -FileId $CloudFile.id
                            if ($RemovePut.resources_affected -eq 1) {
                                Write-Host "Removed cloud file $($CloudFile.id)"
                            }
                        }
                    }
                }
            }
            catch {
                $_
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
                if (($RemovePut.resources_affected -eq 1) -or (-not $CloudFile)) {
                    Write-Host "Uploading $Filename..."
                    $Param = @{
                        Path        = $FilePath
                        Name        = $Filename
                        Description = "$ProcessName"
                        Comment     = "psfalcon: Invoke-FalconDeploy"
                    }
                    $AddPut = Send-FalconPutFile @Param
                    if ($AddPut.resources_affected -ne 1) {
                        break
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
                    if ($Session) {
                        $Param = @{
                            Object = $Session.hosts
                            Step = 'session_start'
                            BatchId = $Session.batch_id
                        }
                        Write-Result @Param
                        $SessionHosts = ($Session.hosts | Where-Object { ($_.complete -eq $true) -or
                        ($_.offline_queued -eq $true) }).aid
                    }
                    if ($SessionHosts) {
                        Write-Host "Pushing $Filename to $($SessionHosts.count) host(s)..."
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
                            $Param = @{
                                Object = $CmdPut
                                Step = 'put_file'
                                BatchId = $Session.batch_id
                            }
                            Write-Result @Param
                            $PutHosts = ($CmdPut | Where-Object { ($_.stdout -eq
                            'Operation completed successfully.') -or ($_.offline_queued -eq $true) }).aid
                        }
                    }
                    if ($PutHosts) {
                        Write-Host "Starting $Filename on $($PutHosts.count) host(s)..."
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
                            $Param = @{
                                Object = $CmdRun
                                Step = 'run_file'
                                BatchId = $Session.batch_id
                            }
                            Write-Result @Param
                        }
                    }
                }
            }
            catch {
                $_
            }
            finally {
                if (Test-Path $OutputFile) {
                    Get-ChildItem $OutputFile | Out-Host
                }
            }
        }
    }
}