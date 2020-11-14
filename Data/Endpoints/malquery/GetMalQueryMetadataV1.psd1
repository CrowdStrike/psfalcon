@{
  Name = "malquery/GetMalQueryMetadataV1"
  Path = "/malquery/entities/metadata/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "malquery:read"
  Description = "Retrieve indexed files metadata by their hash"
  Parameters = @(
    @{
      Dynamic = "FileIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The file SHA256."
      Position = $null
    }
  )
  Responses = @{
    200 = "malquery.SampleMetadataResponse"
    400 = "malquery.SampleMetadataResponse"
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "malquery.SampleMetadataResponse"
  }
}