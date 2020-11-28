@{
  Name = "fwmgr/get-rule-groups"
  Path = "/fwmgr/entities/rule-groups/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Get rule group entities by ID. These groups do not contain their rule entites just the rule IDs in precedence order."
  Parameters = @(
    @{
      Dynamic = "GroupIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more rule group identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "fwmgr.api.RuleGroupsResponse"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}