@{
  Name = "falconx/DeleteReport"
  Path = "/falconx/entities/reports/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-sandbox:write"
  Description = "Delete sandbox reports"
  Parameters = @(
    @{
      Dynamic = "ReportId"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Sandbox report identifier"
      Position = 1
    }
  )
  Responses = @{
    202 = "falconx.QueryResponse"
    400 = "falconx.ErrorsOnly"
    403 = "falconx.ErrorsOnly"
    404 = "falconx.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "falconx.ErrorsOnly"
  }
}