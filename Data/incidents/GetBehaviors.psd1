@{
  Name = "incidents/GetBehaviors"
  Path = "/incidents/entities/behaviors/GET/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "incidents:read"
  Description = "List detailed information about behaviors"
  Parameters = @(
    @{
      Dynamic = "BehaviorIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Min = 1
      Max = 500
      Description = "One or more behavior identifiers"
      Position = $null
    }
  )
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
    default = "api.MsaExternalBehaviorResponse"
  }
}