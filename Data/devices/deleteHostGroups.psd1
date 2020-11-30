@{
  Name = "devices/deleteHostGroups"
  Path = "/devices/entities/host-groups/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "host-group:write"
  Description = "Delete Host Groups"
  Parameters = @(
    @{
      Dynamic = "GroupIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more group identifiers"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}