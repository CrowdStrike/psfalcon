@{
  Name = "samples/DeleteSampleV2"
  Path = "/samples/entities/samples/v2"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-sandbox:write"
  Description = "Removes a sample including file meta and submissions from the collection"
  Parameters = @(
    @{
      Dynamic = "UserUuid"
      Name = "X-CS-USERUUID"
      Type = "string"
      In = @( "header" )
      Required = $false
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
      Position = $null
    }
    @{
      Dynamic = "Sha256"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{64}"
      Description = "Sha256 hash value of the file to remove"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.QueryResponse"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}