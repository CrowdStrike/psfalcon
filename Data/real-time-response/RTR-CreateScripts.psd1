@{
  Name = "real-time-response/RTR-CreateScripts"
  Path = "/real-time-response/entities/scripts/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "multipart/form-data"
  }
  Permission = "real-time-response-admin:write"
  Description = "Upload a new custom-script to use for the RTR 'runscript' command."
  Parameters = @(
    @{
      Dynamic = "Path"
      Name = "file"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Script = '[System.IO.Path]::IsPathRooted($_)'
      ScriptError = "Relative paths are not permitted."
      Description = "Script to upload"
      Position = 1
    }
    @{
      Dynamic = "PermissionType"
      Name = "permission_type"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Enum = @(
        "private"
        "group"
        "public"
      )
      Description = "Permission level"
      Position = 2
    }
    @{
      Dynamic = "Platform"
      Name = "platform"
      Type = "array"
      In = @( "formdata" )
      Enum = @(
        "windows"
        "mac"
      )
      Description = "Operating system platform"
      Position = 3
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Description = "A description of the script"
      Position = 4
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "formdata" )
      Description = "Optional name to use for the script"
      Position = 5
    }
    @{
      Dynamic = "Comment"
      Name = "comments_for_audit_log"
      Type = "string"
      In = @( "formdata" )
      Max = 4096
      Description = "A comment for the audit log"
      Position = 6
    }
    
  )
  Responses = @{
    400 = "domain.APIError"
    default = "msa.ReplyMetaOnly"
  }
}