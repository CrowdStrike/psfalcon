@{
  Name = "real-time-response/RTR-CheckAdminCommandStatus"
  Path = "/real-time-response/entities/admin-command/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Get status of an executed RTR administrator command on a single host."
  Parameters = @(
    @{
      Dynamic = "CloudRequestId"
      Name = "cloud_request_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "Cloud request identifier of the executed command"
      Position = 1
    }
    @{
      Dynamic = "SequenceId"
      Name = "sequence_id"
      Type = "int"
      In = @( "query" )
      Description = "Sequence identifier"
      Position = 2
    }
  )
  Responses = @{
    401 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "domain.StatusResponseWrapper"
  }
}