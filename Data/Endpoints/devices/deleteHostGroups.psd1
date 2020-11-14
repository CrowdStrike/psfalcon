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
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}