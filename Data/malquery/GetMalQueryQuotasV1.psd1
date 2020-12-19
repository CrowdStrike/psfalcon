@{
  Name = "malquery/GetMalQueryQuotasV1"
  Path = "/malquery/aggregates/quotas/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "malquery:read"
  Description = "Get information about search and download quotas in your environment"
  Responses = @{
    400 = "msa.ErrorsOnly"
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "malquery.RateLimitsResponse"
  }
}