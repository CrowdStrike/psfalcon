@{
  Name = "policy/queryCombinedSensorUpdatePoliciesV2"
  Path = "/policy/combined/sensor-update/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "sensor-update-policies:read"
  Description = "Search for Sensor Update Policies with additional support for uninstall protection in your environment by providing an FQL filter and paging details. Returns a set of Sensor Update Policies which match the filter criteria"
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.SensorUpdatePoliciesV2"
  }
}