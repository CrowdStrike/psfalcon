@{
  Name = "malquery/GetMalQueryEntitiesSamplesFetchV1"
  Path = "/malquery/entities/samples-fetch/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/zip"
  }
  Permission = "malquery:read"
  Description = "Download a zip containing Malquery samples (password: infected)"
  Parameters = @(
    @{
      Dynamic = "JobId"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Sample job identifier"
      Position = 1
    }
    @{
      Dynamic = "Path"
      Name = ""
      Type = "String"
      In = @( "outfile" )
      Required = $true
      Pattern = "\.zip$"
      Description = "Destination Path"
      Position = 2
    }
  )
  Responses = @{
    200 = ""
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "malquery.ExternalQueryResponse"
  }
}