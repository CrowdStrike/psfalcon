@{
  Name = "intel/QueryIntelReportIds"
  Path = "/intel/queries/reports/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-reports:read"
  Description = "Get report IDs that match provided FQL filters."
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
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.ErrorsOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
  }
}