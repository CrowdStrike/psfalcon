@{
  Name = "intel/GetIntelReportPDF"
  Path = "/intel/entities/report-files/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/octet-stream"
  }
  Permission = "falconx-reports:read"
  Description = "Download an Intel Report PDF"
  Parameters = @(
    @{
      Dynamic = "ReportId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "The ID of the report you want to download as a PDF."
      Position = $null
    }
    @{
      Dynamic = "Path"
      Name = ""
      Type = "string"
      In = @(
        "outfile"
      )
      Required = $true
      Pattern = "\.pdf$"
      Description = "Destination Path"
      Position = $null
    }
  )
  Responses = @{
    200 = ""
    400 = "msa.ErrorsOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
  }
}