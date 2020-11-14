@{
  Name = "real-time-response/BatchInitSessions"
  Path = "/real-time-response/combined/batch-init-session/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "real-time-response:read"
  Description = "Initialize a Real-time Response session on multiple hosts"
  Parameters = @(
    @{
      Dynamic = "HostIds"
      Name = "host_ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more host identifiers"
      Position = 1
    }
    @{
      Dynamic = "ExistingBatchId"
      Name = "existing_batch_id"
      Type = "string"
      In = @( "body" )
      Required = $false
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "Add hosts to an existing batch session"
      Position = 2
    }
    @{
      Dynamic = "Timeout"
      Name = "timeout"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 30
      Max = 600
      Description = "Length of time to wait for a result in seconds"
      Position = 3
    }
    @{
      Dynamic = "QueueOffline"
      Name = "queue_offline"
      Type = "bool"
      In = @( "body" )
      Required = $false
      Description = "Add sessions in this batch to the offline queue if the hosts do not initialize"
      Position = 4
    }
  )
  Responses = @{
    201 = "domain.BatchInitSessionResponse"
    400 = "domain.APIError"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "domain.APIError"
  }
}