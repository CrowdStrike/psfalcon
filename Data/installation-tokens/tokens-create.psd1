
@{
  Name = "installation-tokens/tokens-create"
  Path = "/installation-tokens/entities/tokens/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "installation-tokens:write"
  Description = "Creates a token."
  Parameters = @(
    @{
      Dynamic = "Label"
      Name = "label"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "The token label."
      Position = 1
    }
    @{
      Dynamic = "ExpiresTimestamp"
      Name = "expires_timestamp"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "The token's expiration time (RFC-3339). Null if the token never expires."
      Position = 2
    }
  )
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}
