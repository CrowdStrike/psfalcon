@{
  Name = "ioarules/get-rule-groups"
  Description = "Get rule groups by ID."
  Path = "/ioarules/entities/rule-groups/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "custom-ioa:read"
  Parameters = @{
    Dynamic = "GroupIds"
    Name = "ids"
    Required = $true
    Description = "One or more rule group identifiers"
    Type = "array"
    In = @(
      "query"
    )
    Pattern = "\w{32}"
    Position = 1
  }
  Responses = @{
    200 = "api.RuleGroupsResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}