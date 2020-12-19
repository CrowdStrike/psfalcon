@{
  Name = "scanner/QuerySubmissions"
  Description = "Find IDs for submitted scans by providing an FQL filter and paging details. Returns a set of volume IDs that match your criteria."
  Path = "/scanner/queries/scans/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "quick-scan:read"
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "mlscanner.QueryResponse"
  }
}