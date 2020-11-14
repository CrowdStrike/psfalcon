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
    @{
      Dynamic = "Password"
      Name = "password"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "The user's password. If left blank the system will generate an email asking them to set their password (recommended)"
      Position = $null
    }
    @{
      Dynamic = "Username"
      Name = "uid"
      Type = "string"
      In = @( "body" )
      Required = $true
      Description = "A username typically an email address"
      Position = $null
    }
  )
  Responses = @{
    201 = "domain.UserMetaDataResponse"
    400 = "msa.EntitiesResponse"
    403 = "msa.EntitiesResponse"
    429 = "msa.ReplyMetaOnly"
  }
}