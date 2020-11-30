@{
  Name = "detects/GetDetectSummaries"
  Path = "/detects/entities/summaries/GET/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "detects:read"
  Description = "List detailed detection information"
  Parameters = @(
    @{
      Dynamic = "DetectionIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Min = 1
      Max = 1000
      Description = "One or more detection identifiers"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "domain.MsaDetectSummariesResponse"
  }
}