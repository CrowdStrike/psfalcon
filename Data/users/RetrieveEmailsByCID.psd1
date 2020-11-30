@{
  Name = "users/RetrieveEmailsByCID"
  Path = "/users/queries/emails-by-cid/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "usermgmt:read"
  Description = "List all usernames (typically an email address)"
  Parameters = @()
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}