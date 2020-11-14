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
      Dynamic = "RoleIds"
      Name = "roleIds"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "One or more roles to assign"
      Position = $null
    }
  )
  Responses = @{
    200 = "domain.UserRoleIDsResponse"
    400 = "msa.EntitiesResponse"
    403 = "msa.EntitiesResponse"
    429 = "msa.ReplyMetaOnly"
  }
}