@{
  Name = "fwmgr/query-events"
  Path = "/fwmgr/queries/events/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Find all event IDs matching the query with filter"
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
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "fwmgr.api.QueryResponse"
  }
}