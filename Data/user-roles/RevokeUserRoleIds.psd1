@{
  Name = "user-roles/RevokeUserRoleIds"
  Path = "/user-roles/entities/user-roles/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:write"
  Description = "Revoke one or more roles from a user"
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
      Dynamic = "RoleIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more roles"
      Position = 2
    }
  )
  Responses = @{
    400 = "msa.EntitiesResponse"
    403 = "msa.EntitiesResponse"
    429 = "msa.ReplyMetaOnly"
    default = "domain.UserRoleIDsResponse"
  }
}