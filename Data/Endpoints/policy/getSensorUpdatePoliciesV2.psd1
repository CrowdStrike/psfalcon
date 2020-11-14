@{
  Name = "policy/getSensorUpdatePoliciesV2"
  Path = "/policy/entities/sensor-update/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-update-policies:read"
  Description = "Retrieve a set of Sensor Update Policies with additional support for uninstall protection by specifying their IDs"
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
    200 = "responses.SensorUpdatePoliciesV2"
    403 = "msa.ErrorsOnly"
    404 = "responses.SensorUpdatePoliciesV2"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.SensorUpdatePoliciesV2"
  }
}