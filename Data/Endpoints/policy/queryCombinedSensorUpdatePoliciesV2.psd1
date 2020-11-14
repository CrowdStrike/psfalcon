@{
  Name = "policy/queryCombinedSensorUpdatePoliciesV2"
  Path = "/policy/combined/sensor-update/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-update-policies:read"
  Description = "Search for Sensor Update Policies with additional support for uninstall protection in your environment by providing an FQL filter and paging details. Returns a set of Sensor Update Policies which match the filter criteria"
  Parameters = @()
  Responses = @{
    200 = "responses.SensorUpdatePoliciesV2"
    400 = "responses.SensorUpdatePoliciesV2"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.SensorUpdatePoliciesV2"
  }
}