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
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "falconx.ReportV1Response"
  }
}