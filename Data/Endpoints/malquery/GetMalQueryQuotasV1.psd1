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
    200 = "malquery.RateLimitsResponse"
    400 = "msa.ErrorsOnly"
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    404 = "malquery.RateLimitsResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "malquery.RateLimitsResponse"
  }
}