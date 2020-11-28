@{
  Name = "fwmgr/get-rules"
  Path = "/fwmgr/entities/rules/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Get rule entities by ID (64-bit unsigned int as decimal string) or Family ID (32-character hexadecimal string)"
  Parameters = @(
    @{
      Dynamic = "RuleIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The rules to retrieve identified by ID"
      Position = $null
    }
  )
  Responses = @{
    200 = "fwmgr.api.RulesResponse"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}