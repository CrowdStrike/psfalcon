@{
  Name = "policy/queryPreventionPolicies"
  Path = "/policy/queries/prevention/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "prevention-policies:read"
  Description = "Search for Prevention Policies in your environment by providing an FQL filter and paging details. Returns a set of Prevention Policy IDs which match the filter criteria"
  Parameters = @()
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}