@{
  Name = "policy/getSensorUpdatePolicies"
  Path = "/policy/entities/sensor-update/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-update-policies:read"
  Description = "Retrieve a set of Sensor Update Policies by specifying their IDs"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The IDs of the Sensor Update Policies to return"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.SensorUpdatePoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.SensorUpdatePoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.SensorUpdatePoliciesV1"
  }
}