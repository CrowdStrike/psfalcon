#Requires -Version 5.1
using module PSFalcon

<#
.SYNOPSIS
Retrieves a specified file from a list of host IDs using Falcon's Real-time Response capabilities.
.PARAMETER HostIds
One or more host IDs for which the file retrieval will be performed.
.PARAMETER FilePath
The file path on the target hosts to retrieve.
.PARAMETER OutputDirectory
The directory where the retrieved file will be saved.
.EXAMPLE
.\RetrieveFileFromHosts.ps1 -HostIds "xxxxxxxxxxxxxx", "xxxxxxxxxxxx" -FilePath "C:\hello.txt" -OutputDirectory "C:\"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string[]]$HostIds,

    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

begin {
    # Start the Falcon session for the specified host IDs
    Write-Verbose "Starting Falcon session for hosts: $($HostIds -join ', ')"
    $session = Start-FalconSession -Id $HostIds -ErrorAction Stop

    $batchId = $session.batch_id
    Write-Verbose "Session started with Batch ID: $batchId"
}

process {
    try {
        # Invoke the batch get command to retrieve the specified file
        Write-Verbose "Requesting file '$FilePath' from hosts in batch $batchId"
        $batchGet = Invoke-FalconBatchGet -FilePath $FilePath -BatchId $batchId -ErrorAction Stop

        $batchGetCmdReqId = $batchGet.batch_get_cmd_req_id
        Write-Verbose "Batch get command request ID: $batchGetCmdReqId"

        # Confirm the file retrieval, with a retry mechanism for SHA256
        $retryCount = 5
        $sha256 = $null
        $sessionId = $null

        for ($i = 1; $i -le $retryCount; $i++) {
            Write-Verbose "Attempt ${i}: Confirming file retrieval for Batch Get Cmd Req ID: $batchGetCmdReqId"
            $fileConfirmation = Confirm-FalconGetFile -BatchGetCmdReqId $batchGetCmdReqId -ErrorAction Stop

            # Check if SHA256 is available
            if ($fileConfirmation.sha256) {
                $sha256 = $fileConfirmation.sha256
                $sessionId = $fileConfirmation.session_id
                Write-Verbose "File confirmation successful. SHA256: $sha256, Session ID: $sessionId"
                break
            } else {
                Write-Verbose "SHA256 not available yet. Retrying in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }

        # Exit if SHA256 is still not retrieved after retries
        if (-not $sha256) {
            Write-Error "SHA256 hash for the file could not be retrieved after multiple attempts. Exiting."
            return
        }

	# Remove leading and trailing quotes from OutputDirectory
	$OutputDirectory = $OutputDirectory -replace '(^"|"$)', ''
	Write-Host "Sanitized Output Directory: '$OutputDirectory'"

	# Trim and resolve the OutputDirectory path
	$OutputDirectory = $OutputDirectory.Trim()
	$resolvedOutputDirectory = Resolve-Path -Path $OutputDirectory -ErrorAction Stop
	Write-Host "Resolved Output Directory: '$resolvedOutputDirectory'"

        # Construct the full output path
        $outputFilePath = Join-Path -Path $resolvedOutputDirectory -ChildPath "$($FilePath | Split-Path -Leaf).7z"
        Write-Verbose "Downloading file to $outputFilePath"
        
        # Download the file
        Receive-FalconGetFile -Path $outputFilePath -Sha256 $sha256 -SessionId $sessionId -ErrorAction Stop

        Write-Host "File successfully downloaded to $outputFilePath"

    } catch {
        Write-Error "An error occurred during the process: $_"
        throw $_
    }
}

end {
    Write-Verbose "Script completed."
}
