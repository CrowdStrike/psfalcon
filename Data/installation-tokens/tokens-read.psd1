
@{
  Name = "installation-tokens/tokens-read"
  Path = "/installation-tokens/entities/tokens/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "installation-tokens:read"
  Description = "Gets the details of one or more tokens by id."
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
  )
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
    default = "api.tokenDetailsResponseV1"
  }
}
