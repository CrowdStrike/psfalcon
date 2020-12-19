@{
  Name = "samples/QuerySampleV1"
  Path = "/samples/queries/samples/GET/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "falconx-sandbox:write"
  Description = "Retrieve information about sandbox submission files"
  Parameters = @(
    @{
      Dynamic = "UserId"
      Name = "X-CS-USERUUID"
      Type = "string"
      In = @( "header" )
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
    }
    @{
      Dynamic = "Sha256s"
      Name = "sha256s"
      Type = "array"
      In = @( "body" )
      Max = 500
      Pattern = "\w{64}"
      Description = "One or more Sha256 hash values"
    }
  )
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}