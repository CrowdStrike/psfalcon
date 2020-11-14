@{
  Name = "users/RetrieveUserUUIDsByCID"
  Path = "/users/queries/user-uuids-by-cid/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:read"
  Description = "List all user identifiers"
  Parameters = @(
    @{
      Dynamic = "Names"
      Type = "switch"
      Required = $false
      Description = "Retrieve usernames (typically email addresses) rather than user identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
  }
}