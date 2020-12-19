@{
  Name = "users/UpdateUser"
  Path = "/users/entities/users/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:write"
  Description = "Modify an existing user's first or last name"
  Parameters = @(
    @{
      Dynamic = "UserId"
      Name = "user_uuid"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
      Position = 1
    }
    @{
      Dynamic = "FirstName"
      Name = "firstName"
      Type = "string"
      In = @( "body" )
      Description = "User's first name"
      Position = 2
    }
    @{
      Dynamic = "LastName"
      Name = "lastName"
      Type = "string"
      In = @( "body" )
      Description = "User's last name"
      Position = 3
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