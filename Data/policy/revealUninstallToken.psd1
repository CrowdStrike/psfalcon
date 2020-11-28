@{
  Name = "policy/revealUninstallToken"
  Path = "/policy/combined/reveal-uninstall-token/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-update-policies:write"
  Description = "Reveal an uninstall token for a specific device or use 'MAINTENANCE' to reveal the bulk token"
  Parameters = @(
    @{
      Dynamic = "AuditMessage"
      Name = "audit_message"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "A comment to append to the audit log"
      Position = $null
    }
    @{
      Dynamic = "HostId"
      Name = "device_id"
      Type = "string"
      In = @( "body" )
      Required = $true
      Pattern = "\w{32}"
      Description = "Host identifier"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.RevealUninstallTokenRespV1"
    400 = "responses.RevealUninstallTokenRespV1"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.RevealUninstallTokenRespV1"
  }
}