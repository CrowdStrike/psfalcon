@{
  Name = "falconx/GetReports"
  Path = "/falconx/entities/reports/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-sandbox:read"
  Description = "Get a full sandbox report."
  Parameters = @(
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
    200 = "falconx.ReportV1Response"
    400 = "falconx.ReportV1Response"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "falconx.ReportV1Response"
  }
}