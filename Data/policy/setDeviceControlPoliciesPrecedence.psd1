@{
  Name = "policy/setDeviceControlPoliciesPrecedence"
  Path = "/policy/entities/device-control-precedence/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "device-control-policies:write"
  Description = "Sets the precedence of Device Control Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "All of the policy identifiers for the specified platform"
      Position = $null
    }
    @{
      Dynamic = "PlatformName"
      Name = "platform_name"
      Type = "string"
      In = @( "body" )
      Required = $true
      Enum = @(
        "Windows"
        "Mac"
        "Linux"
      )
      Description = "Platform name"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}