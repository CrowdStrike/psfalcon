@{
  Name = "devices/queryCombinedHostGroups"
  Path = "/devices/combined/host-groups/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "host-group:read"
  Description = "Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set of Host Groups which match the filter criteria"
  Parameters = @()
  Responses = @{
    200 = "responses.HostGroupsV1"
    400 = "responses.HostGroupsV1"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.HostGroupsV1"
  }
}