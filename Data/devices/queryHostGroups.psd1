@{
  Name = "devices/queryHostGroups"
  Path = "/devices/queries/host-groups/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "host-group:read"
  Description = "Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set of Host Group IDs which match the filter criteria"
  Parameters = @()
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}