@{
  Name = "oauth2/oauth2RevokeToken"
  Path = "/oauth2/revoke"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/x-www-form-urlencoded"
  }
  Description = "Revoke your current OAuth2 access token before the end of its standard lifespan"
  Parameters = @()
  Responses = @{
    default = "msa.ReplyMetaOnly"
  }
}