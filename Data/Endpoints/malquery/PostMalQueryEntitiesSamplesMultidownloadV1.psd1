@{
  Name = "malquery/PostMalQueryEntitiesSamplesMultidownloadV1"
  Path = "/malquery/entities/samples-multidownload/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "malquery:write"
  Description = "Schedule samples for download from MalQuery"
  Parameters = @(
    @{
      Dynamic = "SampleIds"
      Name = "samples"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "List of sample sha256 ids"
      Position = $null
    }
  )
  Responses = @{
    200 = "malquery.ExternalQueryResponse"
    400 = "malquery.ExternalQueryResponse"
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    404 = "malquery.ExternalQueryResponse"
    429 = "malquery.ExternalQueryResponse"
    500 = "malquery.ExternalQueryResponse"
  }
}