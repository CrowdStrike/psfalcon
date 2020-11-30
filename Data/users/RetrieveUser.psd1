@{
  Name = "users/RetrieveUser"
  Path = "/users/entities/users/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:read"
  Description = "Get detailed information about a user"
  Parameters = @(
    @{
      Dynamic = "UserIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "One or more user identifiers"
      Position = 1
    }
  )
  Responses = @{
    400 = "msa.EntitiesResponse"
    403 = "msa.EntitiesResponse"
    404 = "msa.EntitiesResponse"
    429 = "msa.ReplyMetaOnly"
    default = "domain.UserMetaDataResponse"
  }
}