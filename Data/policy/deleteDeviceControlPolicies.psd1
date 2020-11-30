@{
  Name = "policy/deleteDeviceControlPolicies"
  Path = "/policy/entities/device-control/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "device-control-policies:write"
  Description = "Delete Device Control policies"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more policy identifiers"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}