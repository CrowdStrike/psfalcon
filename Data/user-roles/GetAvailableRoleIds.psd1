@{
  Name = "user-roles/GetAvailableRoleIds"
  Path = "/user-roles/queries/user-role-ids-by-cid/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:read"
  Description = "List user role identifiers"
  Parameters = @()
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}