@{
  Name = "fwmgr/query-platforms"
  Path = "/fwmgr/queries/platforms/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Get the list of platform names"
  Parameters = @()
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "fwmgr.msa.QueryResponse"
  }
}