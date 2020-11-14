@{
  Name = "real-time-response/RTR-CheckActiveResponderCommandStatus"
  Path = "/real-time-response/entities/active-responder-command/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response:write"
  Description = "Check the status of an Active Responder Real-time Response command"
  Parameters = @(
    @{
      Dynamic = "CloudRequestId"
      Name = "cloud_request_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "Cloud request identifier of the executed command"
      Position = $null
    }
    @{
      Dynamic = "SequenceId"
      Name = "sequence_id"
      Type = "int"
      In = @( "query" )
      Required = $false
      Description = "Sequence identifier @(default: 0)"
      Position = $null
    }
  )
  Responses = @{
    200 = "domain.StatusResponseWrapper"
    401 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}