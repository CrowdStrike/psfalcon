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
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.HostGroupMembersV1"
  }
}