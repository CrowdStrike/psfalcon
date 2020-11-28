@{
  Name = "policy/getDeviceControlPolicies"
  Path = "/policy/entities/device-control/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "device-control-policies:read"
  Description = "List detailed Device Control Policy information"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The IDs of the Device Control Policies to return"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.DeviceControlPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.DeviceControlPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.DeviceControlPoliciesV1"
  }
}