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
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "falconx.SubmissionV1Response"
  }
}