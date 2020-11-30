
@{
  Name = "installation-tokens/tokens-delete"
  Path = "/installation-tokens/entities/tokens/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "installation-tokens:write"
  Description = "Deletes a token immediately. To revoke a token use PATCH /installation-tokens/entities/tokens/v1 instead."
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
    default = "msa.ReplyMetaOnly"
  }
}
