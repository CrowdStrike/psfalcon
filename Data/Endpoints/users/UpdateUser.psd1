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
      Dynamic = "UserUuid"
      Name = "user_uuid"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
      Position = $null
    }
    @{
      Dynamic = "FirstName"
      Name = "firstName"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "User's first name"
      Position = $null
    }
    @{
      Dynamic = "LastName"
      Name = "lastName"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "User's last name"
      Position = $null
    }
  )
  Responses = @{
    200 = "domain.UserMetaDataResponse"
    400 = "msa.EntitiesResponse"
    403 = "msa.EntitiesResponse"
    404 = "msa.EntitiesResponse"
    429 = "msa.ReplyMetaOnly"
  }
}