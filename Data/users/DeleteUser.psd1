@{
  Name = "users/DeleteUser"
  Path = "/users/entities/users/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:write"
  Description = "Delete a user"
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
  )
  Responses = @{
    200 = "msa.ReplyMetaOnly"
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}