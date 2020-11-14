@{
  Name = "oauth2/oauth2RevokeToken"
  Path = "/oauth2/revoke"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/x-www-form-urlencoded"
  }
  Description = "Revoke your current OAuth2 access token before the end of its standard lifespan"
  Responses = @{
    200 = "msa.ReplyMetaOnly"
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}