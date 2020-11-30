@{
  Name = "ioarules/get-patterns"
  Description = "Get pattern severities by ID."
  Path = "/ioarules/entities/pattern-severities/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:read"
  Parameters = @{
    Dynamic = "SeverityIds"
    Name = "ids"
    Type = "array"
    In = @( "query" )
    Required = $true
    Pattern = "(critical|high|medium|low|informational)"
    Description = "One or more rule severity identifiers"
    Position = 1
  }
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.PatternsResponse"
  }
}