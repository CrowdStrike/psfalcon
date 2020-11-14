@{
  Name = "devices/getHostGroups"
  Path = "/devices/entities/host-groups/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "host-group:read"
  Description = "List detailed information about Host Groups"
  Parameters = @(
    @{
      Dynamic = "GroupIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "The IDs of the Host Groups to return"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.HostGroupsV1"
    400 = "responses.HostGroupsV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.HostGroupsV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.HostGroupsV1"
  }
}