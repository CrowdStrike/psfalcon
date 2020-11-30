@{
  Name = "devices/queryGroupMembers"
  Path = "/devices/queries/host-group-members/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "host-group:read"
  Description = "Search for members of a Host Group in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria"
  Parameters = @(
    @{
      Dynamic = "GroupId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "The ID of the Host Group to search for members of"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}