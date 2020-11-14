@{
  Name = "ioarules/get-rule-types"
  Description = "Get rule types by ID."
  Path = "/ioarules/entities/rule-types/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:read"
  Parameters = @{
    Dynamic = "TypeIds"
    Name = "ids"
    Required = $true
    Description = "One or more rule type identifiers"
    Type = "array"
    In = @(
      "query"
    )
    Position = 1
  }
  Responses = @{
    200 = "api.RuleTypesResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}