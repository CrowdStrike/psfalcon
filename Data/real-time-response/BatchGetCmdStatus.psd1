@{
  Name = "real-time-response/BatchGetCmdStatus"
  Path = "/real-time-response/combined/batch-get-command/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response:write"
  Description = "Retrieve the status of a 'get' command issued to a batch Real-time Response session"
  Parameters = @(
    @{
      Dynamic = "Timeout"
      Name = "timeout"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 30
      Max = 600
      Description = "Length of time to wait for a result in seconds"
      Position = $null
    }
    @{
      Dynamic = "BatchGetCmdReqId"
      Name = "batch_get_cmd_req_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Batch 'get' command request identifier"
      Position = $null
    }
  )
  Responses = @{
    400 = "domain.APIError"
    403 = "msa.ErrorsOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
    500 = "domain.APIError"
    default = "domain.BatchGetCmdStatusResponse"
  }
}