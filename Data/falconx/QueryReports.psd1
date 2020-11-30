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
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}