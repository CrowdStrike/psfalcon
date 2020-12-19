@{
  Name = "samples/GetMetadataV2"
  Path = "/samples/entities/metadata/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "*/*"
  }
  Permission = "samplestore:read"
  Description = "Retrieves metadata information about a sample."
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
      Dynamic = "FileIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The file sha256."
    }
  )
}