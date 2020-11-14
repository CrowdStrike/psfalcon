@{
  Name = "detects/UpdateDetectsByIdsV2"
  Path = "/detects/entities/detects/v2"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "detects:write"
  Description = "Modify the state assignee and visibility of detections"
  Parameters = @(
    @{
      Dynamic = "AssignedUuid"
      Name = "assigned_to_uuid"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "A user identifier to use to assign the detection"
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = $null
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "A comment to add to the detection"
      Position = $null
    }
    @{
      Dynamic = "DetectionIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Pattern = "ldt:\w{32}:\w+"
      Max = 1000
      Description = "One or more detection identifiers"
      Position = $null
    }
    @{
      Dynamic = "ShowInUi"
      Name = "show_in_ui"
      Type = "bool"
      In = @( "body" )
      Required = $false
      Description = "Display the detection in the Falcon UI"
      Position = $null
    }
    @{
      Dynamic = "Status"
      Name = "status"
      Type = "string"
      In = @( "body" )
      Required = $false
      Enum = @(
        "new"
        "in_progress"
        "true_positive"
        "false_positive"
        "ignored"
      )
      Description = "Detection status"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.ReplyMetaOnly"
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}