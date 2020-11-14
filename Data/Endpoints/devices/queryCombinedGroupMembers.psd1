@{
  Name = "devices/queryCombinedGroupMembers"
  Path = "/devices/combined/host-group-members/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "host-group:read"
  Description = "Search for members of a Host Group in your environment by providing an FQL filter and paging details. Returns a set of host details which match the filter criteria"
  Parameters = @(
    @{
      Dynamic = "GroupId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "Host group identifier"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.HostGroupMembersV1"
    400 = "responses.HostGroupMembersV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.HostGroupMembersV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.HostGroupMembersV1"
  }
}