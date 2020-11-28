@{
  Name = "real-time-response/RTR-UpdateScripts"
  Path = "/real-time-response/entities/scripts/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "multipart/form-data"
  }
  Permission = "real-time-response-admin:write"
  Description = "Upload a new script to replace an existing one"
  Parameters = @(
    @{
      Dynamic = "ScriptId"
      Name = "id"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Description = "The identifier of the script to update"
      Position = $null
    }
    @{
      Dynamic = "Path"
      Name = "file"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Description = "Script to upload"
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Description = "A description of the script"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Description = "Optional name to use for the script"
      Position = $null
    }
    @{
      Dynamic = "Comment"
      Name = "comments_for_audit_log"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Max = 4096
      Description = "A comment for the audit log"
      Position = $null
    }
    @{
      Dynamic = "PermissionType"
      Name = "permission_type"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Description = "Permission level @(private: uploader only group: admins public: admins and active responders)"
      Position = $null
    }
    @{
      Dynamic = "Platform"
      Name = "platform"
      Type = "array"
      In = @( "formdata" )
      Required = $false
      Description = "Operating system platform @(default: windows)"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.ReplyMetaOnly"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}