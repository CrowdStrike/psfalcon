@{
  Name = "devices/performGroupAction"
  Path = "/devices/entities/host-group-actions/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "host-group:write"
  Description = "Perform the specified action on the Host Groups specified in the request"
  Parameters = @(
    @{
      Dynamic = "ActionName"
      Name = "action_name"
      Type = "string"
      In = @( "query" )
      Required = $true
      Enum = @(
        "add-hosts"
        "remove-hosts"
      )
      Description = "The action to perform on the target Host Groups"
      Position = $null
    }
    @{
      Dynamic = "GroupId"
      Name = "ids"
      Type = "string"
      In = @( "body" )
      Required = $true
      Pattern = "\w{32}"
      Description = "Host group identifier"
      Position = $null
    }
    @{
      Dynamic = "FilterName"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "action_parameters"
      Required = $true
      Enum = @(
        "device_id"
        "domain"
        "external_ip"
        "groups"
        "hostname"
        "local_ip"
        "mac_address"
        "os_version"
        "ou"
        "platform_name"
        "site"
        "system_manufacturer"
      )
      Description = "FQL filter name"
      Position = $null
    }
    @{
      Dynamic = "FilterValue"
      Name = "value"
      Type = "array"
      In = @( "body" )
      Parent = "action_parameters"
      Required = $true
      Max = 500
      Description = "One or more values for use with the FQL filter"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.HostGroupsV1"
    400 = "responses.HostGroupsV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.HostGroupsV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.HostGroupsV1"
  }
}