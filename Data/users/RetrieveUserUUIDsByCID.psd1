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
      Dynamic = "Usernames"
      Type = "switch"
      Required = $false
      Description = "Retrieve usernames (typically email addresses) rather than user identifiers"
      Position = $null
    }
  )
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}