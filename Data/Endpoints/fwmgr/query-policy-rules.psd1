@{
  Name = "fwmgr/query-policy-rules"
  Path = "/fwmgr/queries/policy-rules/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Find all firewall rule IDs matching the query with filter and return them in precedence order"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "The ID of the policy container within which to query"
      Position = $null
    }
    @{
      Dynamic = "Query"
      Name = "q"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Perform a generic substring search across all fields"
      Position = $null
    }
  )
  Responses = @{
    200 = "fwmgr.api.QueryResponse"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}