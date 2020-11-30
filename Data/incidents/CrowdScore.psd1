@{
  Name = "incidents/CrowdScore"
  Path = "/incidents/combined/crowdscores/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "incidents:read"
  Description = "List CrowdScore values"
  Parameters = @(
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 2500
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
    default = "api.MsaEnvironmentScoreResponse"
  }
}