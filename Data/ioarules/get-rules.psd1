@{
  Name = "ioarules/get-rules"
  Description = "Get rules by ID and optionally version in the following format: ID@(:version)"
  Path = "/ioarules/entities/rules/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:read"
  Parameters = @{
    Dynamic = "RuleIds"
    Name = "ids"
    Required = $true
    Description = "One or more rule identifiers"
    Type = "array"
    In = @(
      "query"
    )
    Position = 1
  }
  Responses = @{
    200 = "api.RulesResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}