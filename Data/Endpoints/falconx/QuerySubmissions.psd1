@{
  Name = "falconx/QuerySubmissions"
  Path = "/falconx/queries/submissions/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-sandbox:read"
  Description = "Find submission IDs for uploaded files by providing an FQL filter and paging details. Returns a set of submission IDs that match your criteria."
  Parameters = @()
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}