@{
  Name = "users/CreateUser"
  Path = "/users/entities/users/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:write"
  Description = "Create a user"
  Parameters = @(
    @{
      Dynamic = "Username"
      Name = "uid"
      Type = "string"
      In = @( "body" )
      Required = $true
      Description = "An email address or username"
      Position = 1
    }
    @{
      Dynamic = "FirstName"
      Name = "firstName"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "User's first name"
      Position = 2
    }
    @{
      Dynamic = "LastName"
      Name = "lastName"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "User's last name"
      Position = 3
    }
    @{
      Dynamic = "Password"
      Name = "password"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "The user's password. If left blank the system will generate an email asking them to set their password (recommended)"
      Position = 4
    }
  )
  Responses = @{
    201 = "domain.UserMetaDataResponse"
    400 = "msa.EntitiesResponse"
    403 = "msa.EntitiesResponse"
    429 = "msa.ReplyMetaOnly"
  }
}