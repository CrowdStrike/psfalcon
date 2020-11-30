@{
  Name = "falconx/GetSummaryReports"
  Path = "/falconx/entities/report-summaries/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-sandbox:read"
  Description = "Get a short summary version of a sandbox report."
  Parameters = @(
    @{
      Dynamic = "ReportIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more report identifiers"
      Position = 1
    }
    @{
      Dynamic = "Summary"
      Type = "switch"
      Required = $true
      Description = "Retrieve summary information"
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "falconx.SummaryReportV1Response"
  }
}