@{
  Name = "devices/PerformActionV2"
  Path = "/devices/entities/devices-actions/v2"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "devices:write"
  Description = "Perform actions on Hosts"
  Parameters = @(
    @{
      Dynamic = "ActionName"
      Name = "action_name"
      Type = "string"
      In = @( "query" )
      Required = $true
      Enum = @(
        "contain"
        "lift_containment"
        "hide_host"
        "unhide_host"
      )
      Description = "The action to perform on the target Hosts"
      Position = $null
    }
    @{
      Dynamic = "HostIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more Host identifiers"
      Position = $null
    }
  )
  Responses = @{
    202 = "msa.ReplyAffectedEntities"
    400 = "msa.ReplyAffectedEntities"
    403 = "msa.ReplyMetaOnly"
    409 = "msa.ReplyAffectedEntities"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyAffectedEntities"
  }
}