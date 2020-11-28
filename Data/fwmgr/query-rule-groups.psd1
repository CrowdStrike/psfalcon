@{
  Name = "fwmgr/query-rule-groups"
  Path = "/fwmgr/queries/rule-groups/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Find all rule group IDs matching the query with filter"
  Parameters = @(
    @{
      Dynamic = "Query"
      Name = "q"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Perform a generic substring search across all fields"
      Position = $null
    }
    @{
      Dynamic = "After"
      Name = "after"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "A pagination token used with the Limit parameter to manage pagination of results"
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