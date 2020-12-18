@{
  Name = "samples/DeleteSampleV3"
  Method = "delete"
  Path = "/samples/entities/samples/v3"
  Description = "Removes a sample, including file, meta and submissions from the collection"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "samplestore:write"
  Parameters = @(
    @{
      Dynamic = "UserId"
      Name = "X-CS-USERUUID"
      Type = "string"
      In = @( "header" )
      Required = $true
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
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}
