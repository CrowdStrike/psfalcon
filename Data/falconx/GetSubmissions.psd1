@{
  Name = "falconx/GetSubmissions"
  Path = "/falconx/entities/submissions/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-sandbox:read"
  Description = "Check the status of a sandbox analysis"
  Parameters = @(
    @{
      Dynamic = "SubmissionIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more submission identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "falconx.SubmissionV1Response"
    400 = "falconx.SubmissionV1Response"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "falconx.SubmissionV1Response"
  }
}