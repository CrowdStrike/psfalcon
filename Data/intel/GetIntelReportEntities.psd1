@{
  Name = "intel/GetIntelReportEntities"
  Path = "/intel/entities/reports/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-reports:read"
  Description = "List detailed information about Intel Reports"
  Parameters = @(
    @{
      Dynamic = "ReportIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The IDs of the reports you want to retrieve."
      Position = 1
    }
    @{
      Dynamic = "Fields"
      Name = "fields"
      Type = "array"
      In = @( "query" )
      Required = $false
      Description = "The fields to return or a predefined collection name surrounded by two underscores"
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
    default = "domain.NewsResponse"
  }
}