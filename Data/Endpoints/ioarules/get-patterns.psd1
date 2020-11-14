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
    Required = $true
    Description = "One or more rule severity identifiers"
    Type = "array"
    In = @(
      "query"
    )
    Pattern = "(critical|high|medium|low|informational)"
    Position = 1
  }
  Responses = @{
    200 = "api.PatternsResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}