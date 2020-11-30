
@{
  Name = "installation-tokens/tokens-update"
  Path = "/installation-tokens/entities/tokens/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "installation-tokens:write"
  Description = "Updates one or more tokens. Use this endpoint to edit labels change expiration revoke or restore."
  Parameters = @(
    @{
      Dynamic = "TokenIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more token identifiers"
      Position = 1
    }
    @{
      Dynamic = "Label"
      Name = "label"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "The token label."
      Position = $null
    }
    @{
      Dynamic = "ExpiresTimestamp"
      Name = "expires_timestamp"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "The token's expiration time (RFC-3339). Null if the token never expires."
      Position = $null
    }
    
    @{
      Dynamic = "Revoked"
      Name = "revoked"
      Type = "bool"
      In = @( "body" )
      Required = $false
      Description = "Set to true to revoke the token false to un-revoked it."
      Position = $null
    }
  )
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}
