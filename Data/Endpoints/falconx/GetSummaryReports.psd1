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
      Dynamic = "Summary"
      Type = "switch"
      Required = $true
      Description = "Retrieve summary information"
      Position = $null
    }
    @{
      Dynamic = "ReportIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more report identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "falconx.SummaryReportV1Response"
    400 = "falconx.SummaryReportV1Response"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "falconx.SummaryReportV1Response"
  }
}