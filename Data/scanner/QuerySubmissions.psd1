@{
  Name = "scanner/QuerySubmissions"
  Description = "Find IDs for submitted scans by providing an FQL filter and paging details. Returns a set of volume IDs that match your criteria."
  Path = "/scanner/queries/scans/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "quick-scan:read"
  Parameters = @()
  Responses = @{
    200 = "mlscanner.QueryResponse"
    400 = "mlscanner.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "mlscanner.QueryResponse"
  }
}