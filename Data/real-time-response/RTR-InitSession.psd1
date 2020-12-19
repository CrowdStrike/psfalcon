@{
  Name = "real-time-response/RTR-InitSession"
  Path = "/real-time-response/entities/sessions/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Initialize a Real-time Response session"
  Parameters = @(
    @{
      Dynamic = "HostId"
      Name = "device_id"
      Type = "string"
      In = @( "body" )
      Required = $true
      Pattern = "\w{32}"
      Description = "Host identifier"
    }
    @{
      Dynamic = "QueueOffline"
      Name = "queue_offline"
      Type = "bool"
      In = @( "body" )
      Description = "Add session to the offline queue if the host does not initialize"
    }
    @{
      Dynamic = "Origin"
      Name = "origin"
      Type = "string"
      In = @( "body" )
      Description = "Optional comment about the creation of the session"
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