@{
  Name = "incidents/PerformIncidentAction"
  Path = "/incidents/entities/incident-actions/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "incidents:write"
  Description = "Perform a set of actions on one or more incidents such as adding tags or comments or updating the incident name or description"
  Parameters = @(
    @{
      Dynamic = "ActionName"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "action_parameters"
      Required = $true
      Enum = @(
        "add_tag"
        "delete_tag"
        "update_description"
        "update_name"
        "update_status"
      )
      Description = "Action to perform"
      Position = $null
    }
    @{
      Dynamic = "ActionValue"
      Name = "value"
      Type = "string"
      In = @( "body" )
      Parent = "action_parameters"
      Required = $true
      Description = "Value for the chosen action"
      Position = $null
    }
    @{
      Dynamic = "IncidentIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Pattern = "inc:\w{32}:\w{32}"
      Description = "One or more Incident identifiers"
      Position = $null
    }
    @{
      Dynamic = "UpdateDetects"
      Name = "update_detects"
      Type = "bool"
      In = @( "query" )
      Required = $false
      Description = "Update the status of 'new' related detections"
      Position = $null
    }
    @{
      Dynamic = "OverwriteDetects"
      Name = "overwrite_detects"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Replace existing status for related detections"
      Position = $null
    }
  )
  Responses = @{
    default = "msa.ReplyMetaOnly"
  }
}