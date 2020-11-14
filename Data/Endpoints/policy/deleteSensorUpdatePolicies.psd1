@{
  Name = "policy/deleteSensorUpdatePolicies"
  Path = "/policy/entities/sensor-update/v1"
  Method = "DELETE"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-update-policies:write"
  Description = "Delete Sensor Update policies"
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