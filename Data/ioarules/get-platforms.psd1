@{
  Name = "ioarules/get-platforms"
  Description = "Get platforms by ID."
  Path = "/ioarules/entities/platforms/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:read"
  Parameters = @{
    Dynamic = "PlatformIds"
    Name = "ids"
    Required = $true
    Description = "One or more platform identifiers"
    Type = "array"
    In = @( "query" )
    Pattern = "(linux|mac|windows)"
    Position = 1
  }
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.PlatformsResponse"
  }
}