@{
  Name = "fwmgr/get-platforms"
  Path = "/fwmgr/entities/platforms/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Get platform names by identifier"
  Parameters = @(
    @{
      Dynamic = "PlatformIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more platform identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "fwmgr.api.PlatformsResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}