@{
  Name = "falconx/QueryReports"
  Path = "/falconx/queries/reports/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-sandbox:read"
  Description = "Find sandbox reports by providing an FQL filter and paging details. Returns a set of report IDs that match your criteria."
  Parameters = @()
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}