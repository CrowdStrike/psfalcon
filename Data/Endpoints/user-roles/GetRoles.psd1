@{
  Name = "user-roles/GetRoles"
  Path = "/user-roles/entities/user-roles/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:read"
  Description = "Get info about a role"
  Parameters = @(
    @{
      Dynamic = "RoleIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more role identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "domain.UserRoleResponse"
    400 = "msa.EntitiesResponse"
    403 = "msa.EntitiesResponse"
    404 = "msa.EntitiesResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.EntitiesResponse"
  }
}