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
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    403 = "msa.ErrorsOnly"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}