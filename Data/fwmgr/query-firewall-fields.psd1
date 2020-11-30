@{
  Name = "fwmgr/query-firewall-fields"
  Path = "/fwmgr/queries/firewall-fields/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Get the firewall field specification IDs for the provided platform"
  Parameters = @(
    @{
      Dynamic = "PlatformId"
      Name = "platform_id"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Get fields configuration for this platform"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "fwmgr.msa.QueryResponse"
  }
}