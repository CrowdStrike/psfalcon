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
  Responses = @{
    200 = "msa.QueryResponse"
    403 = "msa.QueryResponse"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}