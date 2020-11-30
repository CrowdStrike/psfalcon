@{
  Name = "policy/queryCombinedDeviceControlPolicies"
  Path = "/policy/combined/device-control/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "device-control-policies:read"
  Description = "Search for Device Control Policies in your environment by providing an FQL filter and paging details. Returns a set of Device Control Policies which match the filter criteria"
  Parameters = @()
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.DeviceControlPoliciesV1"
  }
}