#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Using Real-time Response, run 'cswindiag' on a list of hosts, wait for results and download them
.PARAMETER HostId
One or more host identifiers
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$HostId
)
begin {
    # Script to check for newly created 'cswindiag' archives
    [string]$CheckDiag = '$CsWinDiag = Get-ChildItem -Path (Join-Path $env:ProgramFiles "CrowdStrike\Rtr\PutRun"' +
        ') -Filter "CSWinDiag*.zip" | Where-Object { $_.LastWriteTime.Ticks -gt {0} } | Select-Object -First 1 |' +
        'Select-Object -ExpandProperty FullName; if ($CsWinDiag) { $CsWinDiag } else { throw "incomplete" }'
}
process {
    try {
        # Filter to Windows hosts
        [string[]]$HostList = $HostId | Select-Object -Unique | Get-FalconHost | Where-Object {
            $_.platform_name -eq 'Windows' } | Select-Object -ExpandProperty device_id
        if ($HostId -and !$HostList) { throw "'CsWinDiag' is only available for Windows hosts." }
        # Create variables to track results
        [System.Collections.Generic.List[string]]$WaitDiag = @()
        @('DiagCreated','Failed','WaitGet').foreach{
            New-Variable -Name $_ -Value ([System.Collections.Generic.List[PSCustomObject]]@())
        }
        # Start batch session
        Write-Host "Starting batch Real-time Response session with $(
            ($HostList | Measure-Object).Count) host(s)..."
        $Batch = Start-FalconSession -Id $HostList -Timeout 60
        if (!$Batch.batch_id) { throw "Failed to create batch Real-time Response session." }
        # Issue 'cswindiag' command
        $Start = (Get-Date).Ticks
        $Cmd = $Batch | Invoke-FalconAdminCommand -Command cswindiag
        foreach ($CmdResult in $Cmd) {
            if ($CmdResult.stdout -eq 'The process was successfully started') {
                $WaitDiag.Add($CmdResult.aid)
            } else {
                $Failed.Add($CmdResult)
            }
        }
        if ($WaitDiag.Count -gt 0) {
            Write-Host "Started 'cswindiag' on $($WaitDiag.Count) host(s). Waiting for result(s)..."
            [string]$Argument = '-Raw=```' + ($CheckDiag -replace '\{0\}',$Start) + '```'
            do {
                # Check each host for diagnostic archive created after $Start
                Start-Sleep -Seconds 30
                $Param = @{
                    BatchId = $Batch.batch_id
                    Command = 'runscript'
                    Argument = $Argument
                    OptionalHostId = $WaitDiag
                }
                $Cmd = Invoke-FalconAdminCommand @Param
                foreach ($ScriptResult in ($Cmd | Where-Object { $_.stdout })) {
                    # When archive is created, gather aid and path to archive
                    Write-Host "Result created for host '$($ScriptResult.aid)'."
                    $DiagCreated.Add($ScriptResult)
                    [void]$WaitDiag.Remove($ScriptResult.aid)
                }
                if ($WaitDiag.Count -gt 0) {
                    Write-Host "Waiting for result(s)... [$(($DiagCreated.Count/($DiagCreated.Count +
                        $WaitDiag.Count)).ToString("P")) complete]"
                }
            } until ( $WaitDiag.Count -eq 0 )
            if ($DiagCreated -eq 0) { throw "No 'cswindiag' result(s) created." }
            foreach ($FileResult in $DiagCreated) {
                # Issue 'get' for each archive on each host
                Write-Host "Issuing 'get' for host '$($FileResult.aid)'..."
                $Param = @{
                    BatchId = $Batch.batch_id
                    FilePath = "'$($FileResult.stdout)'"
                    OptionalHostId = $FileResult.aid
                }
                (Invoke-FalconBatchGet @Param).hosts | ForEach-Object { $WaitGet.Add($_) }
            }
            if ($WaitGet -eq 0) { throw "No 'get' commands successfully issued." }
            do {
                $ConfirmHost = $WaitGet | Where-Object { $null -ne $_.stdout -and $_.complete -eq $true }
                if ($null -ne $ConfirmHost) {
                    # Check 'get' results every 30 seconds
                    Write-Host "Waiting for upload(s)... [$((($ConfirmHost |
                        Measure-Object).Count/$WaitGet.Count).ToString("P")) complete]"
                    Start-Sleep -Seconds 30
                    foreach ($Item in $ConfirmHost) {
                        $Item | Confirm-FalconGetFile | ForEach-Object {
                            if ($_.sha256) {
                                # Receive diagnostic
                                $_ | Receive-FalconGetFile -Path "$($_.name | Split-Path -Leaf).7z"
                                ($WaitGet | Where-Object { $_.session_id -eq $Item.session_id }) | ForEach-Object {
                                    # Remove 'stdout' to exclude from further processing
                                    $_.stdout = $null
                                }
                            }
                        }
                    }
                }
            } until ( $null -eq $ConfirmHost )
        }
        # Output failures
        if ($Failed.Count -gt 0) { $Failed }
    } catch {
        throw $_
    }
}