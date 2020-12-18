@{
  Name = "user-roles/GrantUserRoleIds"
  Path = "/user-roles/entities/user-roles/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:write"
  Description = "Assign one or more roles to a user"
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
      Name = "roleIds"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "One or more roles to assign"
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