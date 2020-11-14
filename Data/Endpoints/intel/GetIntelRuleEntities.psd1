@{
  Name = "intel/GetIntelRuleEntities"
  Path = "/intel/entities/rules/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-rules:read"
  Description = "List detailed information about Intel Rules"
  Parameters = @(
    @{
      Dynamic = "RuleIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The ids of rules to return."
      Position = $null
    }
  )
  Responses = @{
    200 = "domain.RulesResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
  }
}