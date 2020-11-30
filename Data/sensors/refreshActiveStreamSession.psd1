@{
  Name = "sensors/refreshActiveStreamSession"
  Path = "/sensors/entities/datafeed-actions/v1/<partition>"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "streaming:read"
  Description = "Refresh an active event stream. Use the URL shown in a GET /sensors/entities/datafeed/v2 response."
  Parameters = @(
    @{
      Dynamic = "ActionName"
      Name = "action_name"
      Type = "string"
      In = @( "query" )
      Required = $true
      Enum = @(
        "refresh_active_stream_session"
      )
      Description = "Action name. Allowed value is refresh_active_stream_session."
      Position = $null
    }
    @{
      Dynamic = "AppId"
      Name = "appId"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{1,32}"
      Description = "Label that identifies your connection. Max: 32 alphanumeric characters (a-z A-Z 0-9)."
      Position = $null
    }
    @{
      Dynamic = "Partition"
      Name = "<partition>"
      Type = "int"
      In = @( "path" )
      Required = $true
      Description = "Partition to request data for."
      Position = $null
    }
  )
  Responses = @{
    default = "msa.ReplyMetaOnly"
  }
}