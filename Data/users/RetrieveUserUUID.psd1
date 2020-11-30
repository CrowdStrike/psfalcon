@{
  Name = "users/RetrieveUserUUID"
  Path = "/users/queries/user-uuids-by-email/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:read"
  Description = "Retrieve a user identifier by providing a username (typically an email address)"
  Parameters = @(
    @{
      Dynamic = "Username"
      Name = "uid"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "Email address or username"
      Position = 1
    }
  )
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}