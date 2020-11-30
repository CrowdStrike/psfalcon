@{
  Name = "user-roles/GetUserRoleIds"
  Path = "/user-roles/queries/user-role-ids-by-user-uuid/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:read"
  Description = "Show role IDs of roles assigned to a user"
  Parameters = @(
    @{
      Dynamic = "UserUuid"
      Name = "user_uuid"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
      Position = 1
    }
  )
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}