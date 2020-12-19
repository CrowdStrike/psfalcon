@{
  Name = "oauth2/oauth2AccessToken"
  Path = "/oauth2/token"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/x-www-form-urlencoded"
  }
  Description = "Generate an OAuth2 access token"
  Parameters = @(
    @{
      Dynamic = "Id"
      Name = "client_id"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{32}"
      Description = "The API client ID to authenticate your API requests"
      Position = 1
    }
    @{
      Dynamic = "Secret"
      Name = "client_secret"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{40}"
      Description = "The API client secret to authenticate your API requests"
      Position = 2
    }
    @{
      Dynamic = "Cloud"
      Type = "string"
      Enum = @(
        "eu-1"
        "us-gov-1"
        "us-1"
        "us-2"
      )
      Description = "Destination CrowdStrike cloud"
      Position = 3
    }
    @{
      Dynamic = "CID"
      Name = "member_cid"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{32}"
      Description = "For MSSP Master CIDs optionally lock the token to act on behalf of this member CID"
      Position = 4
    }
  )
  Responses = @{
    201 = "domain.AccessTokenResponseV1"
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}