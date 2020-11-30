@{
  Name = "intel/QueryIntelReportEntities"
  Path = "/intel/combined/reports/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-reports:read"
  Description = "Get info about reports that match provided FQL filters."
  Parameters = @(
    @{
      Dynamic = "Query"
      Name = "q"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Perform a generic substring search across all fields"
      Position = $null
    }
    @{
      Dynamic = "Fields"
      Name = "fields"
      Type = "array"
      In = @( "query" )
      Required = $false
      Description = "The fields to return or a predefined collection name surrounded by two underscores"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
    default = "domain.NewsResponse"
  }
}