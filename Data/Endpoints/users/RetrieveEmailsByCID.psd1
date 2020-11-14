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
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
  }
}