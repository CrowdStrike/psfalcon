@{
  Name = "real-time-response/RTR-PulseSession"
  Path = "/real-time-response/entities/refresh-session/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Refresh a session timeout on a single host."
  Parameters = @(
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
    @{
      Dynamic = "QueueOffline"
      Name = "queue_offline"
      Type = "bool"
      In = @( "body" )
      Required = $false
      Description = "Add session to the offline queue"
      Position = $null
    }
  )
  Responses = @{
    201 = "domain.InitResponseWrapper"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "domain.APIError"
  }
}